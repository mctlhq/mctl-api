// Copyright 2026 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package glovomigrate is the operator-run schema migrator of the Glovo basket
// canary (mctl-api#1006, runbook step D2). It applies, as the migration role and
// in this order, the Glovo base schema, the approval schema v2 and the basket
// schema v1, each in its own transaction, and it can show what it would change
// (dry run) or prove the result without changing anything (verify).
//
// Nothing in cmd/api calls it: boot only verifies schemas. It never prints the
// connection string or any secret.
package glovomigrate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovobasket"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// Mode selects what Run does.
type Mode int

const (
	// ModeApply applies the three schemas in order.
	ModeApply Mode = iota
	// ModeDryRun reads the catalog and prints what ModeApply would do.
	ModeDryRun
	// ModeVerify reads the catalog and succeeds only if all three schemas are
	// exactly what this build needs.
	ModeVerify
)

// Sentinel errors. ExitCode maps them to process exit codes.
var (
	// ErrRefused: a precondition failed before anything was changed (wrong
	// role, DSN without TLS, bad configuration, ownership not transferred).
	ErrRefused = errors.New("glovo-migrate: refused")
	// ErrSchemaNewer: a recorded schema version is above the one compiled into
	// this binary. Nothing was changed.
	ErrSchemaNewer = errors.New("glovo-migrate: a schema is newer than this binary")
	// ErrNotReady: verify read the catalog and found it is not what this build
	// needs.
	ErrNotReady = errors.New("glovo-migrate: schema not ready")
	// ErrCouldNotObserve: a catalog read failed. An unreadable catalog is never
	// reported as clean, empty or absent.
	ErrCouldNotObserve = errors.New("glovo-migrate: could not observe the catalog")
	// ErrLockTimeout: a step waited longer than lock_timeout (SQLSTATE 55P03)
	// for a lock and its transaction was rolled back. Safe to retry.
	ErrLockTimeout = errors.New("glovo-migrate: lock timeout")
	// ErrStepFailed: an apply step failed; its transaction was rolled back and
	// no later step ran.
	ErrStepFailed = errors.New("glovo-migrate: step failed")
)

// Exit codes of cmd/glovo-migrate.
const (
	ExitOK           = 0
	ExitRefused      = 1 // ErrRefused, ErrSchemaNewer
	ExitNotReady     = 2 // ErrNotReady
	ExitCouldNotRead = 3 // ErrCouldNotObserve, ErrLockTimeout, ErrStepFailed, anything else
)

// ExitCode maps an error returned by Run to a process exit code.
func ExitCode(err error) int {
	switch {
	case err == nil:
		return ExitOK
	case errors.Is(err, ErrRefused), errors.Is(err, ErrSchemaNewer):
		return ExitRefused
	case errors.Is(err, ErrNotReady):
		return ExitNotReady
	default:
		return ExitCouldNotRead
	}
}

// DefaultExpectRole is the role the migrator insists on being.
const DefaultExpectRole = "glovo_migrator"

// Default timeouts, applied with SET LOCAL in every transaction.
const (
	DefaultLockTimeout      = 5 * time.Second
	DefaultStatementTimeout = 60 * time.Second
)

var roleNameRE = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// Config is the input of Run.
type Config struct {
	// DSN is the migration connection string. It is never printed.
	DSN string
	// ExpectRole is the role the connection must be (current_user). Default
	// DefaultExpectRole.
	ExpectRole string
	// RuntimeRole is the Glovo runtime role that receives the runtime grants
	// (glovo_runtime).
	RuntimeRole string
	// WorkItemsRole is the work-items role that receives the generic DML grants.
	WorkItemsRole string
	// LockTimeout and StatementTimeout are SET LOCAL in every transaction.
	LockTimeout      time.Duration
	StatementTimeout time.Duration
	Mode             Mode
	// Out receives the progress report. nil discards it.
	Out io.Writer

	// allowInsecureTLS lets the tests, whose scratch Postgres has no TLS,
	// connect. Unexported: no command-line flag reaches it.
	allowInsecureTLS bool
	// onStep, when set, is called with the step name just before it is applied.
	onStep func(name string)
	// ignoreRefusals (tests only) applies the steps even though the preflight
	// found refusals. It is the oracle of the preflight tests: a refusal is
	// only correct if the step it guards would really have failed.
	ignoreRefusals bool
}

// Step names, in apply order.
const (
	StepBase     = "glovo-base"
	StepApproval = "approval-v2"
	StepBasket   = "basket-v1"
)

// StepNames is the enforced order.
func StepNames() []string { return []string{StepBase, StepApproval, StepBasket} }

func (c *Config) withDefaults() {
	if c.ExpectRole == "" {
		c.ExpectRole = DefaultExpectRole
	}
	if c.LockTimeout == 0 {
		c.LockTimeout = DefaultLockTimeout
	}
	if c.StatementTimeout == 0 {
		c.StatementTimeout = DefaultStatementTimeout
	}
	if c.Out == nil {
		c.Out = io.Discard
	}
}

func (c *Config) validate() error {
	for name, r := range map[string]string{"expected role": c.ExpectRole, "runtime role": c.RuntimeRole, "work-items role": c.WorkItemsRole} {
		if !roleNameRE.MatchString(r) {
			return fmt.Errorf("%w: %s %q is not a valid role name", ErrRefused, name, r)
		}
	}
	if c.RuntimeRole == c.WorkItemsRole {
		return fmt.Errorf("%w: the runtime role and the work-items role must differ", ErrRefused)
	}
	if c.RuntimeRole == c.ExpectRole || c.WorkItemsRole == c.ExpectRole {
		return fmt.Errorf("%w: the migration role may not also be the runtime or work-items role", ErrRefused)
	}
	if c.LockTimeout < time.Millisecond || c.StatementTimeout < time.Millisecond {
		return fmt.Errorf("%w: timeouts must be at least 1ms (0 would disable them)", ErrRefused)
	}
	return nil
}

// CheckDSN refuses a connection string whose effective sslmode is not at least
// require (require, verify-ca or verify-full), a Unix-socket host (no TLS), and
// one that does not name the expected role. It reads PG* environment variables
// the way pgx does, so a PGSSLMODE cannot weaken it. The error never echoes the
// string.
func CheckDSN(dsn, expectRole string) error {
	pc, err := pgconn.ParseConfig(dsn)
	if err != nil {
		return fmt.Errorf("%w: the DSN is not parseable", ErrRefused)
	}
	cfgs := append([]*pgconn.FallbackConfig{{Host: pc.Host, TLSConfig: pc.TLSConfig}}, pc.Fallbacks...)
	for _, f := range cfgs {
		if f.TLSConfig == nil || strings.HasPrefix(f.Host, "/") {
			return fmt.Errorf("%w: the DSN must use sslmode=require (or verify-ca, verify-full) over TCP", ErrRefused)
		}
	}
	if pc.User != expectRole {
		return fmt.Errorf("%w: the DSN user is not the expected role %q", ErrRefused, expectRole)
	}
	return nil
}

// Run executes cfg.Mode. It returns nil only when the mode's goal was reached:
// applied and verified, planned (dry run), or verified clean.
func Run(ctx context.Context, cfg Config) (err error) {
	cfg.withDefaults()
	defer func() { err = redact(err, cfg.DSN) }()
	if err := cfg.validate(); err != nil {
		return err
	}
	if cfg.DSN == "" {
		return fmt.Errorf("%w: no DSN given", ErrRefused)
	}
	if cfg.allowInsecureTLS {
		pc, perr := pgconn.ParseConfig(cfg.DSN)
		if perr != nil {
			return fmt.Errorf("%w: the DSN is not parseable", ErrRefused)
		}
		if pc.User != cfg.ExpectRole {
			return fmt.Errorf("%w: the DSN user is not the expected role %q", ErrRefused, cfg.ExpectRole)
		}
	} else if err := CheckDSN(cfg.DSN, cfg.ExpectRole); err != nil {
		return err
	}

	// Preflight: one read-only transaction that proves the identity and reads
	// every step's state. Nothing is changed before all three are known.
	states, err := preflight(ctx, &cfg)
	if err != nil {
		return err
	}
	for _, s := range states {
		say(cfg.Out, "%s\n", s.describe(cfg.Mode))
	}
	for _, s := range states {
		if s.newer() {
			return fmt.Errorf("%w: %s records %s, above what this binary applies; nothing was changed", ErrSchemaNewer, s.name, s.recordedText())
		}
	}

	switch cfg.Mode {
	case ModeDryRun:
		for _, s := range states {
			if len(s.refusals) > 0 {
				say(cfg.Out, "dry-run: a real run would REFUSE at %s: %s\n", s.name, strings.Join(s.refusals, "; "))
			}
		}
		say(cfg.Out, "%s\n", "dry-run: nothing was applied")
		return nil
	case ModeVerify:
		return verdict(&cfg, states)
	}

	// Apply. Refuse up front what a step would refuse later, so a known
	// precondition never leaves an earlier step committed alone.
	for _, s := range states {
		if len(s.refusals) > 0 && !cfg.ignoreRefusals {
			return fmt.Errorf("%w: %s: %s; nothing was changed", ErrRefused, s.name, strings.Join(s.refusals, "; "))
		}
	}
	for _, st := range steps(&cfg) {
		if cfg.onStep != nil {
			cfg.onStep(st.name)
		}
		say(cfg.Out, "applying %s ...\n", st.name)
		if aerr := st.apply(ctx); aerr != nil {
			say(cfg.Out, "FAILED %s; its transaction was rolled back and no later step ran\n", st.name)
			var pe *pgconn.PgError
			switch {
			case errors.Is(aerr, ErrRefused):
				return aerr
			case errors.As(aerr, &pe) && pe.Code == "55P03":
				return fmt.Errorf("%w: %s waited more than %s for a lock; rolled back, safe to retry in a quieter window: %w", ErrLockTimeout, st.name, cfg.LockTimeout, aerr)
			default:
				return fmt.Errorf("%w: %s: %w", ErrStepFailed, st.name, aerr)
			}
		}
		say(cfg.Out, "applied %s\n", st.name)
	}
	// The result is proven by reading it back, never assumed from the commits.
	after, err := preflight(ctx, &cfg)
	if err != nil {
		return err
	}
	return verdict(&cfg, after)
}

func verdict(cfg *Config, states []stepState) error {
	var bad []string
	for _, s := range states {
		if !s.ready() {
			bad = append(bad, s.name)
		}
	}
	if len(bad) > 0 {
		say(cfg.Out, "NOT READY: %s\n", strings.Join(bad, ", "))
		return fmt.Errorf("%w: %s", ErrNotReady, strings.Join(bad, ", "))
	}
	say(cfg.Out, "%s\n", "READY: all three schemas are at the version this binary applies")
	return nil
}

type stepRunner struct {
	name  string
	apply func(ctx context.Context) error
}

// steps is the enforced order. Each Apply* runs its own transaction(s) with
// setup first, under the same migration role.
func steps(cfg *Config) []stepRunner {
	return []stepRunner{
		{StepBase, func(ctx context.Context) error {
			return glovo.ApplySchema(ctx, cfg.DSN, cfg.RuntimeRole, glovo.WithTxSetup(cfg.setup))
		}},
		{StepApproval, func(ctx context.Context) error {
			return workitems.ApplyGlovoApprovalSchema(ctx, cfg.DSN, cfg.RuntimeRole,
				workitems.WithWorkItemsRole(cfg.WorkItemsRole), workitems.WithTxSetup(cfg.setup))
		}},
		{StepBasket, func(ctx context.Context) error {
			return glovobasket.ApplySchema(ctx, cfg.DSN, cfg.RuntimeRole, glovobasket.WithTxSetup(cfg.setup))
		}},
	}
}

// setup is the first statement block of every transaction: the timeouts, local
// to the transaction, then a re-check of the role and that it is not a superuser (the connection string could
// have changed between the preflight and this connection).
func (c *Config) setup(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, fmt.Sprintf(`SET LOCAL lock_timeout = '%dms'`, c.LockTimeout.Milliseconds())); err != nil {
		return fmt.Errorf("set lock_timeout: %w", err)
	}
	if _, err := tx.Exec(ctx, fmt.Sprintf(`SET LOCAL statement_timeout = '%dms'`, c.StatementTimeout.Milliseconds())); err != nil {
		return fmt.Errorf("set statement_timeout: %w", err)
	}
	var cur string
	var super bool
	if err := tx.QueryRow(ctx, `SELECT current_user::text, (SELECT rolsuper FROM pg_roles WHERE rolname = current_user)`).Scan(&cur, &super); err != nil {
		return fmt.Errorf("read the current role: %w", err)
	}
	if cur != c.ExpectRole {
		return fmt.Errorf("%w: connected as a role other than %q", ErrRefused, c.ExpectRole)
	}
	if super {
		return fmt.Errorf("%w: the migration role must not be a superuser", ErrRefused)
	}
	return nil
}

// redact removes the DSN, and the password and user:password parts inside it,
// from an error before it leaves Run. The wrapped chain is kept for errors.Is.
func redact(err error, dsn string) error {
	if err == nil || dsn == "" {
		return err
	}
	secrets := []string{dsn}
	if pc, perr := pgconn.ParseConfig(dsn); perr == nil && pc.Password != "" {
		secrets = append(secrets, pc.Password)
	}
	msg := err.Error()
	out := msg
	for _, s := range secrets {
		out = strings.ReplaceAll(out, s, "[redacted]")
	}
	if out == msg {
		return err
	}
	return &redactedError{msg: out, cause: err}
}

type redactedError struct {
	msg   string
	cause error
}

func (e *redactedError) Error() string { return e.msg }
func (e *redactedError) Unwrap() error { return e.cause }

// say writes a progress line; a failing writer must not change the outcome.
func say(w io.Writer, format string, args ...any) { _, _ = fmt.Fprintf(w, format, args...) }
