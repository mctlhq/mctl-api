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

package principals

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/mctlhq/mctl-api/internal/auth"
)

// CustomerDeletion is a frozen, explicitly approved teardown target. It survives
// tenant and principal removal so a retry never resolves a replacement account.
type CustomerDeletion struct {
	Tenant      string `json:"tenant_name"`
	PrincipalID string `json:"principal_id"`
	GitHubID    string `json:"github_id"`
	Login       string `json:"login"`
	Issuer      string `json:"issuer"`
	Subject     string `json:"subject"`
	Actor       string `json:"actor"`
	Status      string `json:"status"`
}

const customerDeletionSchema = `CREATE TABLE IF NOT EXISTS customer_deletions (
 tenant_name TEXT NOT NULL, principal_id TEXT NOT NULL,
 github_id TEXT NOT NULL, login TEXT NOT NULL, issuer TEXT NOT NULL,
 subject TEXT NOT NULL, actor TEXT NOT NULL,
 status TEXT NOT NULL CHECK (status IN ('prepared','deleting','complete')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(), completed_at TIMESTAMPTZ,
 PRIMARY KEY (tenant_name, principal_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS customer_deletion_pending_github
 ON customer_deletions(github_id) WHERE status <> 'complete';
CREATE INDEX IF NOT EXISTS customer_deletion_subject ON customer_deletions(issuer,subject);
CREATE INDEX IF NOT EXISTS customer_deletion_principal ON customer_deletions(principal_id);`

const customerDeletionColumns = `tenant_name,principal_id,github_id,login,issuer,subject,actor,status`

func scanCustomerDeletion(row pgx.Row) (*CustomerDeletion, error) {
	var d CustomerDeletion
	if err := row.Scan(&d.Tenant, &d.PrincipalID, &d.GitHubID, &d.Login, &d.Issuer, &d.Subject, &d.Actor, &d.Status); err != nil {
		return nil, err
	}
	return &d, nil
}

func (s *Store) CustomerDeletion(ctx context.Context, tenant, pid string) (*CustomerDeletion, error) {
	return scanCustomerDeletion(s.pool.QueryRow(ctx, `SELECT `+customerDeletionColumns+` FROM customer_deletions WHERE tenant_name=$1 AND principal_id=$2`, tenant, pid))
}

// WithCustomerDeletionLock serializes external effects across API replicas.
// Its lock is separate from the short store transactions used by each stage.
func (s *Store) WithCustomerDeletionLock(ctx context.Context, tenant, pid string, fn func() error) error {
	return s.withTx(ctx, "customer-deletion-run|"+tenant+"|"+pid, func(pgx.Tx) error { return fn() })
}

// PrepareCustomerDeletion accepts a human with exactly a GitHub identity and a
// customer ZITADEL identity, never a staff/service account or a mixed principal.
// The caller must independently verify ownership, all memberships and IdP org.
func (s *Store) PrepareCustomerDeletion(ctx context.Context, tenant, pid, issuer, actor string, validate ...func(*CustomerDeletion) error) (*CustomerDeletion, error) {
	if tenant == "" || !auth.ValidPrincipalID(pid) || issuer == "" || actor == "" {
		return nil, ErrInvalid
	}
	var result *CustomerDeletion
	err := s.withTx(ctx, "customer-deletion|"+tenant+"|"+pid, func(tx pgx.Tx) error {
		if err := lockPrincipalTx(ctx, tx, pid); err != nil {
			return err
		}
		previous, err := scanCustomerDeletion(tx.QueryRow(ctx, `SELECT `+customerDeletionColumns+` FROM customer_deletions WHERE tenant_name=$1 AND principal_id=$2`, tenant, pid))
		if err == nil {
			for _, check := range validate {
				if err := check(previous); err != nil {
					return err
				}
			}
			result = previous
			return nil
		}
		if err != pgx.ErrNoRows {
			return err
		}
		p, err := getPrincipalTx(ctx, tx, pid)
		if err != nil {
			return err
		}
		if p.Kind != auth.KindHuman || p.Status != StatusActive {
			return fmt.Errorf("%w: target is not an active human", ErrInvalid)
		}
		rows, err := tx.Query(ctx, `SELECT provider,issuer,subject,display,revoked_at IS NOT NULL FROM external_identities WHERE principal_id=$1`, pid)
		if err != nil {
			return err
		}
		d := &CustomerDeletion{Tenant: tenant, PrincipalID: pid, Issuer: issuer, Actor: actor, Status: "prepared"}
		count := 0
		for rows.Next() {
			var provider, iss, sub, display string
			var revoked bool
			if err := rows.Scan(&provider, &iss, &sub, &display, &revoked); err != nil {
				rows.Close()
				return err
			}
			count++
			if revoked {
				rows.Close()
				return fmt.Errorf("%w: revoked identity needs reconciliation", ErrInvalid)
			}
			switch {
			case provider == auth.ProviderGitHub && iss == "":
				d.GitHubID = sub
				d.Login = display
			case provider == "zitadel" && iss == issuer:
				d.Subject = sub
			default:
				rows.Close()
				return fmt.Errorf("%w: principal has an unrelated identity", ErrInvalid)
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if count != 2 || d.GitHubID == "" || d.Subject == "" || strings.TrimSpace(d.Login) == "" {
			return fmt.Errorf("%w: target is not a complete customer identity", ErrInvalid)
		}
		for _, check := range validate {
			if err := check(d); err != nil {
				return err
			}
		}
		_, err = tx.Exec(ctx, `INSERT INTO customer_deletions (`+customerDeletionColumns+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, d.Tenant, d.PrincipalID, d.GitHubID, d.Login, d.Issuer, d.Subject, d.Actor, d.Status)
		result = d
		return err
	})
	return result, err
}

func (s *Store) CustomerDeletionPending(ctx context.Context, githubID string) (bool, error) {
	var pending bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM customer_deletions WHERE github_id=$1 AND status<>'complete')`, githubID).Scan(&pending)
	return pending, err
}

func (s *Store) CustomerSubjectDeleted(ctx context.Context, issuer, subject string) (bool, error) {
	var deleted bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM customer_deletions WHERE issuer=$1 AND subject=$2 AND status IN ('deleting','complete'))`, issuer, subject).Scan(&deleted)
	return deleted, err
}

func (s *Store) CustomerPrincipalDeleted(ctx context.Context, pid string) (bool, error) {
	var deleted bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM customer_deletions WHERE principal_id=$1 AND status IN ('deleting','complete'))`, pid).Scan(&deleted)
	return deleted, err
}

// BeginCustomerDeletion closes the principal before any external teardown. The
// manifest remains retryable if an IdP or session provider is unavailable.
func (s *Store) BeginCustomerDeletion(ctx context.Context, tenant, pid string) error {
	return s.withTx(ctx, "customer-deletion|"+tenant+"|"+pid, func(tx pgx.Tx) error {
		if err := lockPrincipalTx(ctx, tx, pid); err != nil {
			return err
		}
		var status string
		if err := tx.QueryRow(ctx, `SELECT status FROM customer_deletions WHERE tenant_name=$1 AND principal_id=$2 FOR UPDATE`, tenant, pid).Scan(&status); err != nil {
			return err
		}
		if status == "complete" {
			return nil
		}
		tag, err := tx.Exec(ctx, `UPDATE principals SET status='disabled' WHERE id=$1 AND kind='human'`, pid)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrNotFound
		}
		var agentTokensExist bool
		if err := tx.QueryRow(ctx, `SELECT to_regclass('public.agent_run_tokens') IS NOT NULL`).Scan(&agentTokensExist); err != nil {
			return err
		}
		if agentTokensExist {
			if _, err := tx.Exec(ctx, `UPDATE agent_run_tokens SET revoked_at=now() WHERE issued_by_principal_id=$1 AND revoked_at IS NULL`, pid); err != nil {
				return err
			}
		}
		_, err = tx.Exec(ctx, `UPDATE customer_deletions SET status='deleting' WHERE tenant_name=$1 AND principal_id=$2`, tenant, pid)
		return err
	})
}

// FinishCustomerDeletion runs only after every external postcondition passed.
// Historical audit records and the non-secret manifest are intentionally kept.
func (s *Store) FinishCustomerDeletion(ctx context.Context, tenant, pid string) error {
	return s.withTx(ctx, "customer-deletion|"+tenant+"|"+pid, func(tx pgx.Tx) error {
		if err := lockPrincipalTx(ctx, tx, pid); err != nil {
			return err
		}
		var status string
		if err := tx.QueryRow(ctx, `SELECT status FROM customer_deletions WHERE tenant_name=$1 AND principal_id=$2 FOR UPDATE`, tenant, pid).Scan(&status); err != nil {
			return err
		}
		if status == "complete" {
			return nil
		}
		if status != "deleting" {
			return ErrInvalid
		}
		for _, query := range []string{
			`DELETE FROM oauth_refresh_tokens WHERE principal_id=$1`,
			`DELETE FROM surface_identity_links WHERE principal=$1`,
			`DELETE FROM surface_identity_challenges WHERE principal=$1`,
			`DELETE FROM external_identities WHERE principal_id=$1`,
			`DELETE FROM principals WHERE id=$1 AND status='disabled' AND kind='human'`,
		} {
			if _, err := tx.Exec(ctx, query, pid); err != nil {
				return err
			}
		}
		_, err := tx.Exec(ctx, `UPDATE customer_deletions SET status='complete',completed_at=now() WHERE tenant_name=$1 AND principal_id=$2`, tenant, pid)
		return err
	})
}
