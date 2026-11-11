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

// Command glovo-migrate is the operator-run schema migrator of the Glovo basket
// canary (mctl-api#1006, runbook step D2). It applies, as the role
// glovo_migrator and in this order, the Glovo base schema, the approval schema
// v2 and the basket schema v1, each in its own transaction.
//
// The connection string is read from the environment variable named by
// -dsn-env (default MCTL_GLOVO_MIGRATE_DSN), never from the command line, and
// is never printed. Exit codes: 0 ok; 1 refused (wrong role, no TLS, newer
// schema, ownership not transferred); 2 verify found the schemas not ready;
// 3 could not observe the catalog, a lock timeout, or a step failed.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"

	"github.com/mctlhq/mctl-api/internal/glovomigrate"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("glovo-migrate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dsnEnv := fs.String("dsn-env", "MCTL_GLOVO_MIGRATE_DSN", "name of the environment variable that holds the migration DSN (sslmode=require or stricter)")
	expect := fs.String("expect-role", glovomigrate.DefaultExpectRole, "the role the connection must be")
	runtime := fs.String("runtime-role", "glovo_runtime", "Glovo runtime role that receives the runtime grants")
	workitems := fs.String("workitems-role", "", "work-items role that receives the generic DML grants (required)")
	lock := fs.Duration("lock-timeout", glovomigrate.DefaultLockTimeout, "SET LOCAL lock_timeout in every transaction")
	stmt := fs.Duration("statement-timeout", glovomigrate.DefaultStatementTimeout, "SET LOCAL statement_timeout in every transaction")
	dry := fs.Bool("dry-run", false, "read the catalog and print what would change; apply nothing")
	verify := fs.Bool("verify", false, "read the catalog and exit non-zero unless all three schemas are ready; change nothing")
	if err := fs.Parse(args); err != nil {
		return glovomigrate.ExitRefused
	}
	if *dry && *verify {
		_, _ = fmt.Fprintln(stderr, "glovo-migrate: -dry-run and -verify are mutually exclusive")
		return glovomigrate.ExitRefused
	}
	mode := glovomigrate.ModeApply
	switch {
	case *dry:
		mode = glovomigrate.ModeDryRun
	case *verify:
		mode = glovomigrate.ModeVerify
	}
	dsn := os.Getenv(*dsnEnv)
	if dsn == "" {
		_, _ = fmt.Fprintf(stderr, "glovo-migrate: the environment variable %s is empty\n", *dsnEnv)
		return glovomigrate.ExitRefused
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	err := glovomigrate.Run(ctx, glovomigrate.Config{
		DSN: dsn, ExpectRole: *expect, RuntimeRole: *runtime, WorkItemsRole: *workitems,
		LockTimeout: *lock, StatementTimeout: *stmt, Mode: mode, Out: stdout,
	})
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
	}
	return glovomigrate.ExitCode(err)
}
