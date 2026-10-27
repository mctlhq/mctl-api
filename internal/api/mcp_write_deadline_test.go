package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// With the extension the handler may outlive the server's WriteTimeout (here
// scaled to 100ms) and still deliver its response; without it, it may not.
func TestExtendWriteDeadline(t *testing.T) {
	slow := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(250 * time.Millisecond)
		_, _ = w.Write([]byte("late"))
	})
	run := func(h http.Handler) (string, error) {
		srv := httptest.NewUnstartedServer(h)
		srv.Config.WriteTimeout = 100 * time.Millisecond
		srv.Start()
		defer srv.Close()
		resp, err := http.Get(srv.URL)
		if err != nil {
			return "", err
		}
		defer func() { _ = resp.Body.Close() }()
		b, err := io.ReadAll(resp.Body)
		return string(b), err
	}
	if got, err := run(extendWriteDeadlineAbove(100*time.Millisecond, 2*time.Second, slow)); err != nil || got != "late" {
		t.Fatalf("extended: %q %v", got, err)
	}
	if got, err := run(extendWriteDeadlineAbove(100*time.Millisecond, 100*time.Millisecond, slow)); err == nil && got == "late" {
		t.Fatal("at the threshold the deadline must not be extended")
	}
	if got, err := run(slow); err == nil && got == "late" {
		t.Fatal("control: the short WriteTimeout did not apply")
	}
}

// POST /mcp gets the longer request deadline; every other route keeps the default.
func TestRequestTimeout(t *testing.T) {
	deadline := func(mw func(http.Handler) http.Handler, method, target string) time.Duration {
		var left time.Duration
		h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			d, ok := r.Context().Deadline()
			if !ok {
				t.Fatalf("%s %s: no deadline", method, target)
			}
			left = time.Until(d)
		}))
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(method, target, nil))
		return left
	}
	near := func(got, want time.Duration) bool { return got > want-time.Second && got <= want }
	mw := requestTimeout(30*time.Second, 75*time.Second)
	if got := deadline(mw, http.MethodPost, "/mcp"); !near(got, 75*time.Second) {
		t.Fatalf("POST /mcp deadline %s, want 75s", got)
	}
	for _, c := range [][2]string{{http.MethodGet, "/mcp"}, {http.MethodPost, "/api/v1/tenants"}} {
		if got := deadline(mw, c[0], c[1]); !near(got, 30*time.Second) {
			t.Fatalf("%s %s deadline %s, want 30s", c[0], c[1], got)
		}
	}
	if got := deadline(requestTimeout(30*time.Second, 0), http.MethodPost, "/mcp"); !near(got, 30*time.Second) {
		t.Fatalf("unconfigured POST /mcp deadline %s, want 30s", got)
	}
}
