// Package releaseartifact resolves a release (repository and version) to what
// a release grant binds: the commit its git tag points at and the digest of
// the container image published under the same tag, after checking that the
// image was built from that commit (mctl-api#1022).
//
// Every read is checked rather than trusted. A manifest or blob whose bytes do
// not hash to the digest it was fetched by or announced under is a failure,
// as is a tag of an unexpected type, an image without the revision label, or
// a label naming another commit. Two outcomes are kept apart: ErrNotFound is
// GitHub's or the registry's documented 404 for the tag, and everything else
// (a transport error, another status, a malformed body, a missing
// credential) is ErrUnavailable. Callers refuse in both cases; the difference
// is only what they tell the person.
package releaseartifact

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mctlhq/mctl-api/internal/ghtoken"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

var (
	// ErrNotFound: the tag does not exist in git or in the registry.
	ErrNotFound = errors.New("release artifact not found")
	// ErrUnavailable: the artifact could not be read or checked.
	ErrUnavailable = errors.New("release artifact could not be read")
	// ErrMismatch: the artifact was read, and it is not what a release grant
	// may bind (the image was not built from the tag commit).
	ErrMismatch = errors.New("release artifact does not match its tag")
)

// RevisionLabel is the OCI image label that names the source commit.
const RevisionLabel = "org.opencontainers.image.revision"

const (
	defaultGitHubAPI = "https://api.github.com"
	defaultRegistry  = "https://ghcr.io"
	registryService  = "ghcr.io"
	maxBody          = 4 << 20

	mediaOCIIndex      = "application/vnd.oci.image.index.v1+json"
	mediaDockerList    = "application/vnd.docker.distribution.manifest.list.v2+json"
	mediaOCIManifest   = "application/vnd.oci.image.manifest.v1+json"
	mediaDockerImage   = "application/vnd.docker.distribution.manifest.v2+json"
	manifestAccept     = mediaOCIIndex + ", " + mediaDockerList + ", " + mediaOCIManifest + ", " + mediaDockerImage
	attestationRefType = "attestation-manifest"
)

// Resolver reads releases from GitHub and GHCR.
type Resolver struct {
	// Token is a GitHub credential able to read the repository's tags and
	// pull its GHCR package. It is read per call (ghtoken).
	Token ghtoken.Source
	// GitHubAPI and Registry override https://api.github.com and
	// https://ghcr.io (tests only).
	GitHubAPI string
	Registry  string
	// Client is the HTTP client; nil uses a 15 s timeout client.
	Client *http.Client
}

func (r *Resolver) client() *http.Client {
	if r.Client != nil {
		return r.Client
	}
	return &http.Client{Timeout: 15 * time.Second}
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return strings.TrimRight(v, "/")
}

func unavailable(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrUnavailable, fmt.Sprintf(format, args...))
}

// Resolve reads the release and returns the artifact a grant would bind. The
// repository and version are validated first; nothing is fetched for a
// malformed one.
func (r *Resolver) Resolve(ctx context.Context, repository, version string) (workitems.ReleaseArtifact, error) {
	probe := workitems.ReleaseArtifact{Repository: repository, Version: version,
		TagCommit: strings.Repeat("0", 40), ImageDigest: "sha256:" + strings.Repeat("0", 64)}
	if err := probe.Validate(); err != nil {
		return workitems.ReleaseArtifact{}, err
	}
	if r == nil || r.Token == nil {
		return workitems.ReleaseArtifact{}, unavailable("no GitHub credential is configured")
	}
	token, err := ghtoken.Resolve(r.Token)
	if err != nil || token == "" {
		return workitems.ReleaseArtifact{}, unavailable("the GitHub credential could not be read")
	}
	commit, err := r.tagCommit(ctx, token, repository, version)
	if err != nil {
		return workitems.ReleaseArtifact{}, err
	}
	digest, revisions, err := r.image(ctx, token, repository, version)
	if err != nil {
		return workitems.ReleaseArtifact{}, err
	}
	for _, rev := range revisions {
		if rev != commit {
			return workitems.ReleaseArtifact{}, fmt.Errorf("%w: image %s of %s:%s carries %s=%q, the tag points at %s",
				ErrMismatch, digest, repository, version, RevisionLabel, rev, commit)
		}
	}
	art := workitems.ReleaseArtifact{Repository: repository, Version: version, TagCommit: commit, ImageDigest: digest}
	if err := art.Validate(); err != nil {
		return workitems.ReleaseArtifact{}, unavailable("resolved artifact is malformed: %v", err)
	}
	return art, nil
}

// get fetches url and returns the status and at most maxBody bytes. A body
// longer than that is a failure, never a truncated read.
func (r *Resolver) get(ctx context.Context, rawURL string, header http.Header) (int, http.Header, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, nil, nil, unavailable("build request: %v", err)
	}
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := r.client().Do(req)
	if err != nil {
		return 0, nil, nil, unavailable("GET %s: %v", req.URL.Redacted(), err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return 0, nil, nil, unavailable("read %s: %v", req.URL.Redacted(), err)
	}
	if len(body) > maxBody {
		return 0, nil, nil, unavailable("%s answered more than %d bytes", req.URL.Redacted(), maxBody)
	}
	return resp.StatusCode, resp.Header, body, nil
}

type gitObject struct {
	Object struct {
		Type string `json:"type"`
		SHA  string `json:"sha"`
	} `json:"object"`
}

// tagCommit resolves refs/tags/<version> to a commit, through at most one
// annotated tag object.
func (r *Resolver) tagCommit(ctx context.Context, token, repository, version string) (string, error) {
	base := orDefault(r.GitHubAPI, defaultGitHubAPI)
	h := http.Header{"Authorization": {"Bearer " + token}, "Accept": {"application/vnd.github+json"}}
	status, _, body, err := r.get(ctx, base+"/repos/"+repository+"/git/ref/tags/"+url.PathEscape(version), h)
	if err != nil {
		return "", err
	}
	switch status {
	case http.StatusOK:
	case http.StatusNotFound:
		return "", fmt.Errorf("%w: tag %s of %s", ErrNotFound, version, repository)
	default:
		return "", unavailable("tag %s of %s: GitHub answered %d", version, repository, status)
	}
	var ref gitObject
	if err := json.Unmarshal(body, &ref); err != nil {
		return "", unavailable("tag %s of %s: malformed ref: %v", version, repository, err)
	}
	if ref.Object.Type == "tag" {
		status, _, body, err = r.get(ctx, base+"/repos/"+repository+"/git/tags/"+url.PathEscape(ref.Object.SHA), h)
		if err != nil {
			return "", err
		}
		if status != http.StatusOK {
			return "", unavailable("tag object %s of %s: GitHub answered %d", ref.Object.SHA, repository, status)
		}
		var tag gitObject
		if err := json.Unmarshal(body, &tag); err != nil {
			return "", unavailable("tag object %s of %s: malformed: %v", ref.Object.SHA, repository, err)
		}
		ref = tag
	}
	if ref.Object.Type != "commit" || len(ref.Object.SHA) != 40 {
		return "", unavailable("tag %s of %s points at a %q, not a commit", version, repository, ref.Object.Type)
	}
	return strings.ToLower(ref.Object.SHA), nil
}

// registryToken trades the GitHub credential for a pull token of one
// repository.
func (r *Resolver) registryToken(ctx context.Context, token, repository string) (string, error) {
	q := url.Values{"service": {registryService}, "scope": {"repository:" + repository + ":pull"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, orDefault(r.Registry, defaultRegistry)+"/token?"+q.Encode(), nil)
	if err != nil {
		return "", unavailable("build registry token request: %v", err)
	}
	req.SetBasicAuth("x-access-token", token)
	resp, err := r.client().Do(req)
	if err != nil {
		return "", unavailable("registry token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return "", unavailable("registry token: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", unavailable("registry token for %s: answered %d", repository, resp.StatusCode)
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.Token == "" {
		return "", unavailable("registry token for %s: malformed answer", repository)
	}
	return out.Token, nil
}

func sha256Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

type descriptor struct {
	MediaType   string               `json:"mediaType"`
	Digest      string               `json:"digest"`
	Platform    *struct{ OS string } `json:"platform,omitempty"`
	Annotations map[string]string    `json:"annotations,omitempty"`
}

type manifest struct {
	MediaType string       `json:"mediaType"`
	Manifests []descriptor `json:"manifests"`
	Config    *descriptor  `json:"config"`
}

// fetchManifest reads one manifest by tag or digest and checks its bytes
// against the digest the registry announced and, for a digest reference,
// against the reference itself.
func (r *Resolver) fetchManifest(ctx context.Context, pull, repository, reference string) (string, manifest, error) {
	h := http.Header{"Authorization": {"Bearer " + pull}, "Accept": {manifestAccept}}
	status, header, body, err := r.get(ctx, orDefault(r.Registry, defaultRegistry)+"/v2/"+repository+"/manifests/"+url.PathEscape(reference), h)
	if err != nil {
		return "", manifest{}, err
	}
	switch status {
	case http.StatusOK:
	case http.StatusNotFound:
		return "", manifest{}, fmt.Errorf("%w: image %s:%s", ErrNotFound, repository, reference)
	default:
		return "", manifest{}, unavailable("manifest %s:%s: registry answered %d", repository, reference, status)
	}
	digest := sha256Digest(body)
	if announced := header.Get("Docker-Content-Digest"); announced != "" && announced != digest {
		return "", manifest{}, unavailable("manifest %s:%s: body hashes to %s, registry announced %s", repository, reference, digest, announced)
	}
	if strings.HasPrefix(reference, "sha256:") && reference != digest {
		return "", manifest{}, unavailable("manifest %s: body hashes to %s", reference, digest)
	}
	var m manifest
	if err := json.Unmarshal(body, &m); err != nil {
		return "", manifest{}, unavailable("manifest %s:%s: malformed: %v", repository, reference, err)
	}
	if m.MediaType == "" {
		m.MediaType = header.Get("Content-Type")
	}
	return digest, m, nil
}

// revision reads the revision label from one image manifest's config.
func (r *Resolver) revision(ctx context.Context, pull, repository string, m manifest) (string, error) {
	if m.Config == nil || !strings.HasPrefix(m.Config.Digest, "sha256:") {
		return "", unavailable("image manifest of %s has no config", repository)
	}
	h := http.Header{"Authorization": {"Bearer " + pull}}
	status, _, body, err := r.get(ctx, orDefault(r.Registry, defaultRegistry)+"/v2/"+repository+"/blobs/"+m.Config.Digest, h)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", unavailable("config %s of %s: registry answered %d", m.Config.Digest, repository, status)
	}
	if got := sha256Digest(body); got != m.Config.Digest {
		return "", unavailable("config %s of %s hashes to %s", m.Config.Digest, repository, got)
	}
	var cfg struct {
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"config"`
	}
	if err := json.Unmarshal(body, &cfg); err != nil {
		return "", unavailable("config %s of %s: malformed: %v", m.Config.Digest, repository, err)
	}
	rev := cfg.Config.Labels[RevisionLabel]
	if rev == "" {
		return "", fmt.Errorf("%w: image config %s of %s has no %s label", ErrMismatch, m.Config.Digest, repository, RevisionLabel)
	}
	return strings.ToLower(rev), nil
}

// image returns the digest the tag resolves to and the revision label of
// every runnable image under it: the image itself, or each platform image of
// an index. Attestation manifests carry no runnable image and are skipped; an
// index with no runnable image is a failure.
func (r *Resolver) image(ctx context.Context, token, repository, version string) (string, []string, error) {
	pull, err := r.registryToken(ctx, token, repository)
	if err != nil {
		return "", nil, err
	}
	digest, top, err := r.fetchManifest(ctx, pull, repository, version)
	if err != nil {
		return "", nil, err
	}
	switch top.MediaType {
	case mediaOCIManifest, mediaDockerImage:
		rev, err := r.revision(ctx, pull, repository, top)
		if err != nil {
			return "", nil, err
		}
		return digest, []string{rev}, nil
	case mediaOCIIndex, mediaDockerList:
	default:
		return "", nil, unavailable("manifest %s:%s has media type %q", repository, version, top.MediaType)
	}
	var revs []string
	for _, d := range top.Manifests {
		// Skipped only when it is both: an entry with a real platform is
		// what a node pulls, whatever its annotations say.
		if d.Annotations["vnd.docker.reference.type"] == attestationRefType && d.Platform != nil && d.Platform.OS == "unknown" {
			continue
		}
		_, m, err := r.fetchManifest(ctx, pull, repository, d.Digest)
		if err != nil {
			return "", nil, err
		}
		if m.MediaType != mediaOCIManifest && m.MediaType != mediaDockerImage {
			return "", nil, unavailable("index %s of %s lists a %q", digest, repository, m.MediaType)
		}
		rev, err := r.revision(ctx, pull, repository, m)
		if err != nil {
			return "", nil, err
		}
		revs = append(revs, rev)
	}
	if len(revs) == 0 {
		return "", nil, unavailable("index %s of %s lists no runnable image", digest, repository)
	}
	return digest, revs, nil
}
