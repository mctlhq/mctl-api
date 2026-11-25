package main

import (
	"slices"
	"strings"
	"testing"
)

func TestWithDBNameAndRewriteEnv(t *testing.T) {
	got, err := withDBName("postgres://postgres:postgres@localhost:5432/mctl_api_test?sslmode=disable", "ci_pkg_0123456789abcdef")
	if err != nil {
		t.Fatalf("withDBName returned error: %v", err)
	}
	want := "postgres://postgres:postgres@localhost:5432/ci_pkg_0123456789abcdef?sslmode=disable"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}

	if _, err := withDBName("not-a-url", "ci_pkg_0123456789abcdef"); err == nil {
		t.Fatal("expected error for URL missing scheme/host")
	}

	baseEnv := []string{
		"PATH=/usr/bin",
		"TEST_DB_URL=postgres://postgres:postgres@localhost:5432/mctl_api_test?sslmode=disable",
		"TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/mctl_api_test?sslmode=disable",
		"EMPTY_VAR=",
	}
	rewritten, err := rewriteEnv(baseEnv, "ci_pkg_fedcba9876543210")
	if err != nil {
		t.Fatalf("rewriteEnv returned error: %v", err)
	}
	wantEnv := []string{
		"PATH=/usr/bin",
		"TEST_DB_URL=postgres://postgres:postgres@localhost:5432/ci_pkg_fedcba9876543210?sslmode=disable",
		"TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/ci_pkg_fedcba9876543210?sslmode=disable",
		"EMPTY_VAR=",
	}
	if !slices.Equal(rewritten, wantEnv) {
		t.Fatalf("rewritten env mismatch:\ngot:  %v\nwant: %v", rewritten, wantEnv)
	}
}

func TestNewDBNameFormat(t *testing.T) {
	seen := make(map[string]struct{}, 16)
	for range 16 {
		name, err := newDBName()
		if err != nil {
			t.Fatalf("newDBName returned error: %v", err)
		}
		if !validDBName.MatchString(name) {
			t.Fatalf("invalid db name %q", name)
		}
		if _, dup := seen[name]; dup {
			t.Fatalf("duplicate db name %q", name)
		}
		seen[name] = struct{}{}
	}
}

func TestRunNoArgsReturns2(t *testing.T) {
	if code := run(nil, nil); code != 2 {
		t.Fatalf("got exit %d, want 2", code)
	}
}

func TestRunFailClosedOnUnreachablePostgres(t *testing.T) {
	t.Setenv("TEST_DATABASE_URL", "postgres://postgres:postgres@127.0.0.1:1/mctl_api_test?sslmode=disable&connect_timeout=1")
	t.Setenv("TEST_DB_URL", "")
	// Must fail closed without executing child binary when DB provisioning fails.
	code := run([]string{"/bin/echo", "should-not-run"}, []string{
		"TEST_DATABASE_URL=postgres://postgres:postgres@127.0.0.1:1/mctl_api_test?sslmode=disable&connect_timeout=1",
	})
	if code != 1 {
		t.Fatalf("expected exit code 1 when Postgres provisioning fails, got %d", code)
	}
}

func TestRunPassthroughWithoutDBEnv(t *testing.T) {
	t.Setenv("TEST_DATABASE_URL", "")
	t.Setenv("TEST_DB_URL", "")
	code := run([]string{"/bin/sh", "-c", "test \"$TEST_FLAG\" = ok"}, []string{"TEST_FLAG=ok"})
	if code != 0 {
		t.Fatalf("expected passthrough exit 0, got %d", code)
	}
	if !strings.HasPrefix("ci_pkg_0000000000000000", "ci_pkg_") {
		t.Fatal("unreachable")
	}
}
