package api

import (
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Every HTML page the package renders goes through pageShell
// (mctl-api#654): the shell's frame, logo and palette are on each one,
// the title is still escaped, and the headers are the page's own.
func TestEveryPageRendersThroughTheShell(t *testing.T) {
	const (
		oauthCSP = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"
		linkCSP  = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'"
	)
	render := func(f func(w http.ResponseWriter)) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		f(rec)
		return rec
	}
	pages := map[string]struct {
		rec  *httptest.ResponseRecorder
		csp  string
		warn bool
	}{
		"oauth": {render(func(w http.ResponseWriter) {
			renderOAuthPage(w, http.StatusOK, oauthPageData{Title: "<b>t</b>", Primary: &oauthPageLink{Href: "/x", Text: "Go"}})
		}), oauthCSP, false},
		"oauth refusal": {render(func(w http.ResponseWriter) {
			renderOAuthPage(w, http.StatusForbidden, oauthPageData{Title: "<b>t</b>", Lines: []string{"no"}})
		}), oauthCSP, true},
		"link": {render(func(w http.ResponseWriter) {
			renderLinkPage(w, http.StatusOK, linkPageData{Title: "<b>t</b>", Confirm: &struct{ Action, Challenge, CSRF string }{"/c", "ch", "cs"}})
		}), linkCSP, false},
		"link failure": {render(func(w http.ResponseWriter) { linkFailed(w, http.StatusBadRequest, "<b>t</b>") }), linkCSP, true},
		"chooser":      {newCustomerHarnessWith(t, OAuthUpstreamBoth, testCustomersGitHubIdP, true, nil, nil).get(authorizeQuery("")), oauthCSP, false},
	}
	for name, p := range pages {
		body := p.rec.Body.String()
		if !strings.Contains(body, `data-shell="mctl"`) || !strings.Contains(body, `<svg class="logo"`) || !strings.Contains(body, "--primary:#b83d28") || !strings.Contains(body, "prefers-color-scheme:dark") {
			t.Errorf("%s: not drawn in the page shell:\n%s", name, body)
		}
		if !strings.Contains(body, "· MCTL</title>") {
			t.Errorf("%s: the title does not carry the MCTL brand", name)
		}
		if strings.Contains(body, "<b>t</b>") {
			t.Errorf("%s: page text is not escaped", name)
		}
		if got := strings.Contains(body, `class="card warn"`); got != p.warn {
			t.Errorf("%s: warn accent = %v, want %v", name, got, p.warn)
		}
		h := p.rec.Header()
		if h.Get("Content-Security-Policy") != p.csp || h.Get("Cache-Control") != "no-store" || h.Get("X-Frame-Options") != "DENY" || h.Get("Content-Type") != "text/html; charset=utf-8" {
			t.Errorf("%s: headers changed: %v", name, h)
		}
	}

	// The customer entry is the primary button and the account entry the
	// secondary one.
	chooser := pages["chooser"].rec.Body.String()
	if !regexp.MustCompile(`<a href="[^"]*upstream=customer[^"]*">Sign in with GitHub</a>`).MatchString(chooser) ||
		!regexp.MustCompile(`<a class="secondary" href="[^"]*upstream=zitadel[^"]*">Sign in with MCTL account</a>`).MatchString(chooser) {
		t.Errorf("chooser buttons are not customer primary, account secondary:\n%s", chooser)
	}
}

// No page can bypass the shell: page_shell.go is the only file of the
// package that builds an HTML document or imports a template package.
func TestNoPageOutsideTheShell(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("listing package files: %v (%d files)", err, len(files))
	}
	for _, f := range files {
		if f == "page_shell.go" || strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f) //nolint:gosec // a file of this package, from the glob above
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(strings.ToLower(string(src)), "<!doctype html") {
			t.Errorf("%s builds its own HTML document; draw it with shellPage", f)
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), f, src, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		for _, imp := range parsed.Imports {
			if path, _ := strconv.Unquote(imp.Path.Value); path == "html/template" || path == "text/template" {
				t.Errorf("%s imports %s; draw its page with shellPage", f, path)
			}
		}
	}
}
