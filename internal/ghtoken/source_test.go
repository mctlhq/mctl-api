package ghtoken

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStaticAndFileReturnNilWhenUnset(t *testing.T) {
	// Callers check for nil to mean "not configured". A Source that yields ""
	// would make that two conditions instead of one, and the second is the
	// one people forget.
	if Static("") != nil {
		t.Error("Static(\"\") must be nil, not a source yielding an empty string")
	}
	if File("") != nil {
		t.Error("File(\"\") must be nil, not a source yielding an empty string")
	}
}

func TestFileIsReadOnEveryCall(t *testing.T) {
	// The property the package exists for: the platform re-mints an
	// installation token every 30 minutes into this file, and a process that
	// read it once would stop working an hour after it started.
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	src := File(path)

	got, err := src()
	if err != nil || got != "first" {
		t.Fatalf("first read: got %q, %v", got, err)
	}
	if err := os.WriteFile(path, []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = src()
	if err != nil || got != "second" {
		t.Fatalf("after rotation: got %q, %v — the value was cached", got, err)
	}
}

func TestFileTrimsTrailingWhitespace(t *testing.T) {
	// Kubernetes writes Secret values verbatim. A stored trailing newline
	// would travel into an Authorization header and be rejected, for a token
	// that looks correct in every listing.
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("ghs_value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := File(path)()
	if err != nil {
		t.Fatal(err)
	}
	if got != "ghs_value" {
		t.Errorf("got %q, want the value with no trailing newline", got)
	}
}

func TestFileReportsMissingAndEmpty(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent")
	if _, err := File(missing)(); err == nil {
		t.Error("a missing file must be an error, not an empty credential")
	}

	// An empty file is the shape a half-written rotation leaves behind. It
	// must not read as a valid empty token.
	empty := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(empty, []byte("  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := File(empty)()
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("an all-whitespace file must be an error naming it as empty, got %v", err)
	}
}

func TestFirstOfPicksConfigurationNotResult(t *testing.T) {
	// FirstOf chooses once, at wiring time. A file source that later starts
	// failing must surface that error rather than quietly falling through to
	// a stale environment variable — a fallback there would hide exactly the
	// rotation failure this package is meant to make visible.
	boom := errors.New("gone")
	failing := Source(func() (string, error) { return "", boom })

	src := FirstOf(nil, failing, Static("fallback"))
	if _, err := src(); !errors.Is(err, boom) {
		t.Fatalf("want the failing source's error, got %v — it fell through", err)
	}

	if FirstOf(nil, nil) != nil {
		t.Error("FirstOf with nothing configured must be nil")
	}
	got, err := FirstOf(nil, Static("v"))()
	if err != nil || got != "v" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestResolveTreatsNilAsUnset(t *testing.T) {
	got, err := Resolve(nil)
	if err != nil || got != "" {
		t.Fatalf("got %q, %v; nil must resolve to the empty string without error", got, err)
	}
}
