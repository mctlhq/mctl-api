// Package main implements a `go test -exec` wrapper that gives each Go test
// package binary its own disposable PostgreSQL database derived from
// TEST_DATABASE_URL / TEST_DB_URL so `go test -p N ./...` runs without
// cross-package table cleanup races.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const createDBAdvisoryLockID int64 = 783492101

var validDBName = regexp.MustCompile(`^ci_pkg_[0-9a-f]{16}$`)

func main() {
	os.Exit(run(os.Args[1:], os.Environ()))
}

func run(args, baseEnv []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "pgtestexec: missing test binary argument")
		return 2
	}

	dbURL := os.Getenv("TEST_DATABASE_URL")
	altURL := os.Getenv("TEST_DB_URL")
	adminBase := dbURL
	if adminBase == "" {
		adminBase = altURL
	}
	if adminBase == "" {
		return execChild(args, baseEnv)
	}

	dbName, err := newDBName()
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgtestexec: generate database name: %v\n", err)
		return 1
	}

	adminURL, err := withDBName(adminBase, "postgres")
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgtestexec: invalid database url: %v\n", err)
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	if err := createScratchDB(ctx, adminURL, dbName); err != nil {
		cancel()
		fmt.Fprintf(os.Stderr, "pgtestexec: create database %s: %v\n", dbName, err)
		return 1
	}
	cancel()

	defer func() {
		dctx, dcancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer dcancel()
		if derr := dropScratchDB(dctx, adminURL, dbName); derr != nil {
			fmt.Fprintf(os.Stderr, "pgtestexec: warning: drop database %s: %v\n", dbName, derr)
		}
	}()

	childEnv, err := rewriteEnv(baseEnv, dbName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgtestexec: rewrite env: %v\n", err)
		return 1
	}
	return execChild(args, childEnv)
}

func execChild(args, env []string) int {
	// #nosec G204 -- `go test -exec` passes the compiled package test binary and test flags in args.
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode()
		}
		fmt.Fprintf(os.Stderr, "pgtestexec: run %s: %v\n", args[0], err)
		return 1
	}
	return 0
}

func newDBName() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	name := "ci_pkg_" + hex.EncodeToString(b[:])
	if !validDBName.MatchString(name) {
		return "", fmt.Errorf("unexpected db name %q", name)
	}
	return name, nil
}

func withDBName(rawURL, dbName string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("database url missing scheme or host")
	}
	u.Path = "/" + dbName
	return u.String(), nil
}

func rewriteEnv(baseEnv []string, dbName string) ([]string, error) {
	out := make([]string, 0, len(baseEnv))
	for _, entry := range baseEnv {
		k, v, ok := strings.Cut(entry, "=")
		if ok && (k == "TEST_DATABASE_URL" || k == "TEST_DB_URL") && v != "" {
			rewritten, err := withDBName(v, dbName)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", k, err)
			}
			out = append(out, k+"="+rewritten)
			continue
		}
		out = append(out, entry)
	}
	return out, nil
}

func createScratchDB(ctx context.Context, adminURL, dbName string) error {
	if !validDBName.MatchString(dbName) {
		return fmt.Errorf("invalid db name %q", dbName)
	}
	conn, err := pgx.Connect(ctx, adminURL)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close(ctx) }()

	// Serialize CREATE DATABASE across parallel `go test -p N` processes so
	// PostgreSQL does not fail with SQLSTATE 55006 on shared template1.
	if _, lerr := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", createDBAdvisoryLockID); lerr != nil {
		return lerr
	}
	defer func() { _, _ = conn.Exec(ctx, "SELECT pg_advisory_unlock($1)", createDBAdvisoryLockID) }()

	stmt := "CREATE DATABASE " + pgx.Identifier{dbName}.Sanitize()
	// Also retry SQLSTATE 55006 if an external test setup (e.g. glovomigrate)
	// touches template1 concurrently.
	for attempt := range 25 {
		_, err = conn.Exec(ctx, stmt)
		if err == nil {
			return nil
		}
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "55006" || attempt == 24 {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return err
}

func dropScratchDB(ctx context.Context, adminURL, dbName string) error {
	if !validDBName.MatchString(dbName) {
		return fmt.Errorf("invalid db name %q", dbName)
	}
	conn, err := pgx.Connect(ctx, adminURL)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close(ctx) }()

	_, err = conn.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{dbName}.Sanitize()+" WITH (FORCE)")
	return err
}
