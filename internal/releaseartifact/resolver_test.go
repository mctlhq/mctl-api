package releaseartifact

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/ghtoken"
)

const (
	testRepo    = "mctlhq/mctl-api"
	testVersion = "4.163.0"
	testCommit  = "5926cc199f95648ef981bd3aa548464917dac0d1"
	otherCommit = "0000000000000000000000000000000000000001"
	tagObject   = "1111111111111111111111111111111111111111"
)

func digestOf(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// fake is GitHub and GHCR in one server. Its fields are the knobs each test
// turns; the zero changes give a well-formed release built from testCommit.
type fake struct {
	t *testing.T
	// annotated makes the tag ref point at a tag object.
	annotated bool
	refStatus int
	refType   string
	// revision is the label value; noLabel drops the label.
	revision string
	noLabel  bool
	// single serves a plain image manifest instead of an index.
	single bool
	// extraImage adds a second runnable image with otherRevision.
	extraImage    bool
	otherRevision string
	// attestationWithPlatform marks the second image as an attestation but
	// gives it a real platform.
	attestationWithPlatform bool
	tokenStatus             int
	manifestStatus          int
	// lieDigest announces a wrong Docker-Content-Digest.
	lieDigest bool
	// corruptConfig serves config bytes that do not hash to their digest.
	corruptConfig bool

	sawBasic string
}

func (f *fake) server() *httptest.Server {
	rev := f.revision
	if rev == "" {
		rev = testCommit
	}
	labels := map[string]string{RevisionLabel: rev}
	if f.noLabel {
		labels = map[string]string{}
	}
	config := mustJSON(f.t, map[string]any{"config": map[string]any{"Labels": labels}})
	otherRev := f.otherRevision
	if otherRev == "" {
		otherRev = testCommit
	}
	config2 := mustJSON(f.t, map[string]any{"config": map[string]any{"Labels": map[string]string{RevisionLabel: otherRev}}})
	image := mustJSON(f.t, map[string]any{"mediaType": mediaOCIManifest,
		"config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": digestOf(config)}})
	image2 := mustJSON(f.t, map[string]any{"mediaType": mediaOCIManifest,
		"config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": digestOf(config2)}})
	attestation := mustJSON(f.t, map[string]any{"mediaType": mediaOCIManifest,
		"config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": digestOf(config2)}})
	entries := []map[string]any{{"mediaType": mediaOCIManifest, "digest": digestOf(image),
		"platform": map[string]string{"architecture": "amd64", "os": "linux"}}}
	switch {
	case f.extraImage:
		entries = append(entries, map[string]any{"mediaType": mediaOCIManifest, "digest": digestOf(image2),
			"platform": map[string]string{"architecture": "arm64", "os": "linux"}})
	case f.attestationWithPlatform:
		entries = append(entries, map[string]any{"mediaType": mediaOCIManifest, "digest": digestOf(image2),
			"platform":    map[string]string{"architecture": "arm64", "os": "linux"},
			"annotations": map[string]string{"vnd.docker.reference.type": attestationRefType}})
	default:
		entries = append(entries, map[string]any{"mediaType": mediaOCIManifest, "digest": digestOf(attestation),
			"platform":    map[string]string{"architecture": "unknown", "os": "unknown"},
			"annotations": map[string]string{"vnd.docker.reference.type": attestationRefType}})
	}
	index := mustJSON(f.t, map[string]any{"mediaType": mediaOCIIndex, "manifests": entries})
	top := index
	if f.single {
		top = image
	}
	manifests := map[string][]byte{digestOf(image): image, digestOf(image2): image2, digestOf(attestation): attestation}
	blobs := map[string][]byte{digestOf(config): config, digestOf(config2): config2}

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/"+testRepo+"/git/ref/tags/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer gh-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if f.refStatus != 0 {
			w.WriteHeader(f.refStatus)
			return
		}
		typ, sha := "commit", testCommit
		if f.annotated {
			typ, sha = "tag", tagObject
		}
		if f.refType != "" {
			typ = f.refType
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"object": map[string]string{"type": typ, "sha": sha}})
	})
	mux.HandleFunc("/repos/"+testRepo+"/git/tags/"+tagObject, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"object": map[string]string{"type": "commit", "sha": testCommit}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_, pass, _ := r.BasicAuth()
		f.sawBasic = pass
		if f.tokenStatus != 0 {
			w.WriteHeader(f.tokenStatus)
			return
		}
		if r.URL.Query().Get("scope") != "repository:"+testRepo+":pull" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"token": "pull-token"})
	})
	mux.HandleFunc("/v2/"+testRepo+"/manifests/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer pull-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		ref := strings.TrimPrefix(r.URL.Path, "/v2/"+testRepo+"/manifests/")
		var body []byte
		if ref == testVersion {
			if f.manifestStatus != 0 {
				w.WriteHeader(f.manifestStatus)
				return
			}
			body = top
		} else if b, ok := manifests[ref]; ok {
			body = b
		} else {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var m struct {
			MediaType string `json:"mediaType"`
		}
		_ = json.Unmarshal(body, &m)
		w.Header().Set("Content-Type", m.MediaType)
		d := digestOf(body)
		if f.lieDigest && ref == testVersion {
			d = digestOf([]byte("other"))
		}
		w.Header().Set("Docker-Content-Digest", d)
		_, _ = w.Write(body)
	})
	mux.HandleFunc("/v2/"+testRepo+"/blobs/", func(w http.ResponseWriter, r *http.Request) {
		b, ok := blobs[strings.TrimPrefix(r.URL.Path, "/v2/"+testRepo+"/blobs/")]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if f.corruptConfig {
			b = append([]byte(nil), b...)
			b = append(b, ' ')
		}
		_, _ = w.Write(b)
	})
	srv := httptest.NewServer(mux)
	f.t.Cleanup(srv.Close)
	return srv
}

func (f *fake) resolver() *Resolver {
	srv := f.server()
	return &Resolver{Token: ghtoken.Static("gh-token"), GitHubAPI: srv.URL, Registry: srv.URL, Client: srv.Client()}
}

func TestResolveRefusals(t *testing.T) {
	cases := []struct {
		name string
		f    fake
		want error
		msg  string
	}{
		{"tag missing", fake{refStatus: http.StatusNotFound}, ErrNotFound, ""},
		{"github error", fake{refStatus: http.StatusBadGateway}, ErrUnavailable, ""},
		{"tag points at a tree", fake{refType: "tree"}, ErrUnavailable, ""},
		{"registry token refused", fake{tokenStatus: http.StatusForbidden}, ErrUnavailable, ""},
		{"image missing", fake{manifestStatus: http.StatusNotFound}, ErrNotFound, ""},
		{"registry error", fake{manifestStatus: http.StatusInternalServerError}, ErrUnavailable, ""},
		{"announced digest lies", fake{lieDigest: true}, ErrUnavailable, ""},
		{"config bytes do not hash", fake{corruptConfig: true}, ErrUnavailable, ""},
		{"label names another commit", fake{revision: otherCommit}, ErrMismatch, ""},
		{"label missing", fake{noLabel: true}, ErrMismatch, "has no " + RevisionLabel + " label"},
		{"second platform from another commit", fake{extraImage: true, otherRevision: otherCommit}, ErrMismatch, ""},
		{"attestation annotation on a real platform is still checked", fake{attestationWithPlatform: true, otherRevision: otherCommit}, ErrMismatch, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.f.t = t
			_, err := c.f.resolver().Resolve(context.Background(), testRepo, testVersion)
			if !errors.Is(err, c.want) {
				t.Fatalf("Resolve: %v, want %v", err, c.want)
			}
			if c.msg != "" && !strings.Contains(err.Error(), c.msg) {
				t.Fatalf("Resolve: %v, want it to say %q", err, c.msg)
			}
		})
	}
}

func TestResolveRefusesBadInputAndNoCredential(t *testing.T) {
	f := &fake{t: t}
	r := f.resolver()
	for _, in := range [][2]string{{"MctlHQ/mctl-api", testVersion}, {testRepo, "v4.163.0"}, {testRepo, "4.163"}, {"../x", testVersion}} {
		if _, err := r.Resolve(context.Background(), in[0], in[1]); err == nil || errors.Is(err, ErrUnavailable) {
			t.Errorf("Resolve(%q, %q): %v, want an input refusal", in[0], in[1], err)
		}
	}
	r.Token = ghtoken.Static("")
	if _, err := r.Resolve(context.Background(), testRepo, testVersion); !errors.Is(err, ErrUnavailable) {
		t.Errorf("empty credential: %v, want ErrUnavailable", err)
	}
	r.Token = nil
	if _, err := r.Resolve(context.Background(), testRepo, testVersion); !errors.Is(err, ErrUnavailable) {
		t.Errorf("no credential: %v, want ErrUnavailable", err)
	}
}

func TestResolve(t *testing.T) {
	for _, f := range []fake{{}, {annotated: true}, {single: true}, {extraImage: true}} {
		f := f
		f.t = t
		art, err := f.resolver().Resolve(context.Background(), testRepo, testVersion)
		if err != nil {
			t.Fatalf("Resolve %+v: %v", f, err)
		}
		if art.TagCommit != testCommit || art.Repository != testRepo || art.Version != testVersion ||
			!strings.HasPrefix(art.ImageDigest, "sha256:") || len(art.ImageDigest) != 71 {
			t.Errorf("artifact %+v", art)
		}
		if f.sawBasic != "gh-token" {
			t.Errorf("registry token was not requested with the GitHub credential")
		}
	}
}
