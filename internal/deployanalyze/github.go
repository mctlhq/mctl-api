package deployanalyze

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mctlhq/mctl-api/internal/ghtoken"
)

// Sentinels for repository reads. None of them may be read as "absent".
var (
	ErrRevisionUnreadable = errors.New("revision cannot be read")
	ErrGitHubUnavailable  = errors.New("github unavailable")
	ErrGitHubMalformed    = errors.New("github answer malformed")
)

const (
	// The git commit object (not the REST commit, whose files[] patches grow
	// with the diff) is a few hundred bytes.
	commitBodyCap = 64 << 10
	// contentsBodyCap is the largest Contents API answer: GitHub inlines up
	// to 1 MiB, base64 with a newline every 60 chars, plus the JSON envelope.
	// A file over our own limit is detected from "size", never from the body.
	contentsBodyCap = (1<<20)*4/3*61/60 + 64<<10
	// MaxDockerfileBytes and MaxComposeBytes cap decoded file sizes.
	MaxDockerfileBytes = 256 << 10
	MaxComposeBytes    = 128 << 10
)

// FileResult is the outcome of reading one path at a commit.
type FileResult struct {
	Absent   bool
	Kind     string // "file", "dir", "symlink", "submodule"
	Data     []byte
	TooLarge bool
}

// ContentReader reads repository content at a pinned commit.
type ContentReader interface {
	Commit(ctx context.Context, repo, sha string) error
	File(ctx context.Context, repo, sha, path string, maxBytes int) (FileResult, error)
}

// HTTPReader reads through the GitHub REST API.
type HTTPReader struct {
	BaseURL string
	Token   ghtoken.Source
	Client  *http.Client
}

// NewHTTPReader builds a reader with a 10 s timeout.
func NewHTTPReader(baseURL string, token ghtoken.Source) *HTTPReader {
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}
	return &HTTPReader{BaseURL: strings.TrimRight(baseURL, "/"), Token: token, Client: &http.Client{Timeout: 10 * time.Second}}
}

func escapePath(p string) string {
	parts := strings.Split(p, "/")
	for i, s := range parts {
		parts[i] = url.PathEscape(s)
	}
	return strings.Join(parts, "/")
}

func escapeRepo(repo string) (string, error) {
	o, n, ok := strings.Cut(repo, "/")
	if !ok || o == "" || n == "" || strings.Contains(n, "/") {
		return "", fmt.Errorf("invalid repository")
	}
	return url.PathEscape(o) + "/" + url.PathEscape(n), nil
}

// get performs the request and returns status and a body capped at limit.
// Errors never carry the token.
func (h *HTTPReader) get(ctx context.Context, u string, limit int64) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, nil, fmt.Errorf("%w: building request", ErrGitHubUnavailable)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	tok, err := ghtoken.Resolve(h.Token)
	if err != nil || tok == "" {
		return 0, nil, fmt.Errorf("%w: no credential", ErrGitHubUnavailable)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	client := h.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("%w: request failed", ErrGitHubUnavailable)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return 0, nil, fmt.Errorf("%w: reading body", ErrGitHubUnavailable)
	}
	if int64(len(body)) > limit {
		return 0, nil, fmt.Errorf("%w: body over cap", ErrGitHubMalformed)
	}
	return resp.StatusCode, body, nil
}

// Commit requires sha to resolve to exactly itself.
func (h *HTTPReader) Commit(ctx context.Context, repo, sha string) error {
	r, err := escapeRepo(repo)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrGitHubMalformed, err)
	}
	status, body, err := h.get(ctx, h.BaseURL+"/repos/"+r+"/git/commits/"+url.PathEscape(sha), commitBodyCap)
	if err != nil {
		return err
	}
	switch status {
	case http.StatusOK:
	case http.StatusNotFound, http.StatusUnprocessableEntity:
		return ErrRevisionUnreadable
	default:
		return fmt.Errorf("%w: status %d", ErrGitHubUnavailable, status)
	}
	var doc struct {
		SHA string `json:"sha"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("%w: commit body", ErrGitHubMalformed)
	}
	if doc.SHA != sha {
		return fmt.Errorf("%w: commit sha mismatch", ErrGitHubMalformed)
	}
	return nil
}

// File reads path at sha. Call only after Commit succeeded.
func (h *HTTPReader) File(ctx context.Context, repo, sha, path string, maxBytes int) (FileResult, error) {
	r, err := escapeRepo(repo)
	if err != nil {
		return FileResult{}, fmt.Errorf("%w: %v", ErrGitHubMalformed, err)
	}
	u := h.BaseURL + "/repos/" + r + "/contents/" + escapePath(path) + "?ref=" + url.QueryEscape(sha)
	status, body, err := h.get(ctx, u, contentsBodyCap)
	if err != nil {
		return FileResult{}, err
	}
	switch status {
	case http.StatusOK:
	case http.StatusNotFound:
		return FileResult{Absent: true}, nil
	default:
		return FileResult{}, fmt.Errorf("%w: status %d", ErrGitHubUnavailable, status)
	}
	trim := strings.TrimLeft(string(body), " \t\r\n")
	if strings.HasPrefix(trim, "[") {
		var arr []json.RawMessage
		if err := json.Unmarshal(body, &arr); err != nil {
			return FileResult{}, fmt.Errorf("%w: directory body", ErrGitHubMalformed)
		}
		return FileResult{Kind: "dir"}, nil
	}
	var doc struct {
		Type     string  `json:"type"`
		Size     *int    `json:"size"`
		Encoding string  `json:"encoding"`
		Content  *string `json:"content"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return FileResult{}, fmt.Errorf("%w: file body", ErrGitHubMalformed)
	}
	if doc.Type != "file" {
		switch doc.Type {
		case "symlink", "submodule", "dir":
			return FileResult{Kind: doc.Type}, nil
		}
		return FileResult{}, fmt.Errorf("%w: unknown type", ErrGitHubMalformed)
	}
	if doc.Size == nil || *doc.Size < 0 {
		return FileResult{}, fmt.Errorf("%w: missing size", ErrGitHubMalformed)
	}
	if *doc.Size > maxBytes {
		return FileResult{Kind: "file", TooLarge: true}, nil
	}
	if doc.Encoding != "base64" || doc.Content == nil {
		return FileResult{}, fmt.Errorf("%w: missing content", ErrGitHubMalformed)
	}
	data, err := base64.StdEncoding.DecodeString(strings.NewReplacer("\n", "", "\r", "").Replace(*doc.Content))
	if err != nil || len(data) != *doc.Size {
		return FileResult{}, fmt.Errorf("%w: content length mismatch", ErrGitHubMalformed)
	}
	return FileResult{Kind: "file", Data: data}, nil
}
