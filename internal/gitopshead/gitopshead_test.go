package gitopshead

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/ghtoken"
)

const goodSHA = "0123456789abcdef0123456789abcdef01234567"

func resolver(srv *httptest.Server) *Resolver {
	return &Resolver{Token: ghtoken.Static("t"), Repository: "mctlhq/mctl-gitops", Branch: "main", GitHubAPI: srv.URL}
}

func TestHeadReadsTheCommit(t *testing.T) {
	var path, auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, auth = r.URL.Path, r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"object":{"type":"commit","sha":"` + goodSHA + `"}}`))
	}))
	defer srv.Close()
	got, err := resolver(srv).Head(context.Background())
	if err != nil || got != goodSHA {
		t.Fatalf("Head = %q, %v", got, err)
	}
	if path != "/repos/mctlhq/mctl-gitops/git/ref/heads/main" || auth != "Bearer t" {
		t.Errorf("request = %s with %q", path, auth)
	}
}

// Could not observe is never observed absent: every way the read can go wrong
// is ErrUnavailable, and none returns a SHA.
func TestHeadFailuresAreUnavailable(t *testing.T) {
	cases := map[string]struct {
		status int
		body   string
	}{
		"not found":           {404, `{"message":"Not Found"}`},
		"server error":        {500, ``},
		"forbidden":           {403, `{}`},
		"malformed":           {200, `{`},
		"empty object":        {200, `{}`},
		"a tag, not a commit": {200, `{"object":{"type":"tag","sha":"` + goodSHA + `"}}`},
		"short sha":           {200, `{"object":{"type":"commit","sha":"abc"}}`},
		"upper-case sha":      {200, `{"object":{"type":"commit","sha":"` + strings.ToUpper(goodSHA) + `"}}`},
	}
	for name, c := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(c.status)
			_, _ = w.Write([]byte(c.body))
		}))
		got, err := resolver(srv).Head(context.Background())
		srv.Close()
		if !errors.Is(err, ErrUnavailable) || got != "" {
			t.Errorf("%s: Head = %q, %v, want ErrUnavailable and no SHA", name, got, err)
		}
	}
}

func TestHeadRefusesWithoutACredentialOrConfig(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("a request was made")
	}))
	defer srv.Close()
	for name, mutate := range map[string]func(*Resolver){
		"no token":     func(r *Resolver) { r.Token = ghtoken.Static("") },
		"nil token":    func(r *Resolver) { r.Token = nil },
		"bad repo":     func(r *Resolver) { r.Repository = "mctlhq" },
		"upper repo":   func(r *Resolver) { r.Repository = "MctlHQ/mctl-gitops" },
		"bad branch":   func(r *Resolver) { r.Branch = "../x" },
		"empty branch": func(r *Resolver) { r.Branch = "" },
	} {
		r := resolver(srv)
		mutate(r)
		if _, err := r.Head(context.Background()); !errors.Is(err, ErrUnavailable) {
			t.Errorf("%s: %v, want ErrUnavailable", name, err)
		}
	}
}
