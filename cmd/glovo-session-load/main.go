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

// Command glovo-session-load is the one-time, owner-run loader of a Glovo
// consumer session into MCTL's session custody store.
//
// It reads the upstream session JSON from STDIN only (never from a path
// argument, so the file name is not in the process list), keeps the credential
// pair and drops every profile field, seals it with AES-256-GCM and writes it
// to Postgres. It prints the secret-free status and nothing else. It never
// calls Glovo.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mctlhq/mctl-api/internal/glovoprovider/session"
)

type neverRefresh struct{}

func (neverRefresh) Refresh(context.Context, session.Secret) (session.Tokens, error) {
	return session.Tokens{}, errors.New("loader does not refresh")
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "glovo-session-load:", err)
		os.Exit(1)
	}
}

func run() error {
	var tenant, principal, connection, dsnEnv, idEnv, keyEnv string
	var confirm bool
	flag.StringVar(&tenant, "tenant", "", "tenant id of the owner")
	flag.StringVar(&principal, "principal", "", "principal id (prn_...) of the owner")
	flag.StringVar(&connection, "connection", "", "active Glovo connection id (gcn_...) of the owner")
	flag.StringVar(&dsnEnv, "dsn-env", "GLOVO_SESSION_DB_URL", "NAME of the env var holding the Postgres URL")
	flag.StringVar(&idEnv, "kek-id-env", "GLOVO_SESSION_KEK_ID", "NAME of the env var holding the active key id")
	flag.StringVar(&keyEnv, "kek-env", "GLOVO_SESSION_KEKS", "NAME of the env var holding id=base64key[,...]")
	flag.BoolVar(&confirm, "confirm-own-account", false, "assert this session is the operator's OWN Glovo account")
	flag.Parse()
	if !confirm {
		return errors.New("refusing: pass --confirm-own-account (own account only, see mctl-api#1006)")
	}
	key := session.Key{TenantID: tenant, PrincipalID: principal, ConnectionID: connection}
	if tenant == "" || principal == "" || connection == "" {
		return errors.New("--tenant, --principal and --connection are required")
	}
	ring, err := session.KeyringFromEnv(os.Getenv, idEnv, keyEnv)
	if err != nil {
		return err
	}
	if os.Getenv(dsnEnv) == "" {
		return fmt.Errorf("%s is not set", dsnEnv)
	}
	tok, err := session.ParseGlovoSessionFile(os.Stdin, time.Now())
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, os.Getenv(dsnEnv))
	if err != nil {
		return errors.New("cannot open the database pool")
	}
	defer pool.Close()
	m := session.NewManager(session.Config{
		Store: session.NewPostgres(pool, ring), Refresher: neverRefresh{}, Enabled: true, HolderID: "owner-loader",
	})
	st, err := m.Load(ctx, key, tok)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"state": st.State, "generation": st.Generation, "access_expires_at": st.AccessExpiresAt,
	})
}
