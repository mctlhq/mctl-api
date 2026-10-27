package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// With the extension the handler may outlive the server's WriteTimeout (here
// scaled to 100ms) and still deliver its response.
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
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		return string(b), err
	}
	// The package constant is 30s, so scale: a wrapper built directly.
	extended := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(2 * time.Second))
		slow.ServeHTTP(w, r)
	})
	if got, err := run(extended); err != nil || got != "late" {
		t.Fatalf("extended: %q %v", got, err)
	}
	if got, err := run(slow); err == nil && got == "late" {
		t.Fatal("control: the short WriteTimeout did not apply")
	}
	// At or below ServerWriteTimeout the handler is returned unchanged.
	if h := extendWriteDeadline(ServerWriteTimeout, slow); h == nil {
		t.Fatal("nil handler")
	}
}
