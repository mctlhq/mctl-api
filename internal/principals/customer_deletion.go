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
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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
	Cancelled   bool   `json:"cancelled,omitempty"`
}

const customerDeletionSchema = `CREATE TABLE IF NOT EXISTS customer_deletions (
 tenant_name TEXT NOT NULL, principal_id TEXT NOT NULL,
 github_id TEXT NOT NULL, login TEXT NOT NULL, issuer TEXT NOT NULL,
 subject TEXT NOT NULL, actor TEXT NOT NULL,
 status TEXT NOT NULL CHECK (status IN ('prepared','deleting','complete')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(), completed_at TIMESTAMPTZ,
 released_at TIMESTAMPTZ, cancelled_at TIMESTAMPTZ,
 PRIMARY KEY (tenant_name, principal_id)
);
ALTER TABLE customer_deletions ADD COLUMN IF NOT EXISTS released_at TIMESTAMPTZ;
ALTER TABLE customer_deletions ADD COLUMN IF NOT EXISTS cancelled_at TIMESTAMPTZ;
CREATE UNIQUE INDEX IF NOT EXISTS customer_deletion_active_github
 ON customer_deletions(github_id) WHERE status <> 'complete' AND cancelled_at IS NULL;
DROP INDEX IF EXISTS customer_deletion_pending_github;
CREATE INDEX IF NOT EXISTS customer_deletion_subject ON customer_deletions(issuer,subject);
CREATE INDEX IF NOT EXISTS customer_deletion_principal ON customer_deletions(principal_id);`

const customerDeletionColumns = `tenant_name,principal_id,github_id,login,issuer,subject,actor,status`
const customerDeletionSelectColumns = customerDeletionColumns + `,cancelled_at IS NOT NULL`

func scanCustomerDeletion(row pgx.Row) (*CustomerDeletion, error) {
	var d CustomerDeletion
	if err := row.Scan(&d.Tenant, &d.PrincipalID, &d.GitHubID, &d.Login, &d.Issuer, &d.Subject, &d.Actor, &d.Status, &d.Cancelled); err != nil {
		return nil, err
	}
	return &d, nil
}

func (s *Store) CustomerDeletion(ctx context.Context, tenant, pid string) (*CustomerDeletion, error) {
	return scanCustomerDeletion(s.pool.QueryRow(ctx, `SELECT `+customerDeletionSelectColumns+` FROM customer_deletions WHERE tenant_name=$1 AND principal_id=$2`, tenant, pid))
}

// WithCustomerDeletionLock serializes external effects across API replicas.
// Keyed by tenant alone: successive principal owners must not run concurrently.
// The pid argument identifies the target for callers, not the lock granularity.
// Its lock is separate from the short store transactions used by each stage.
func (s *Store) WithCustomerDeletionLock(ctx context.Context, tenant, pid string, fn func(context.Context) error) error {
	select {
	case s.deletionSlots <- struct{}{}:
		defer func() { <-s.deletionSlots }()
	default:
		return errors.New("customer deletion workers busy; retry")
	}
	// Never borrow the authentication pool while nested stage transactions run.
	config := s.pool.Config().ConnConfig.Copy()
	config.RuntimeParams["application_name"] = "mctl-customer-deletion-lock"
	conn, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		return fmt.Errorf("deletion lock connect: %w", err)
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = conn.Close(closeCtx)
	}()
	var acquired bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock(hashtext($1))", "customer-deletion-run|"+tenant).Scan(&acquired); err != nil {
		return err
	}
	if !acquired {
		return errors.New("customer deletion already running; retry")
	}
	// Closing this dedicated session releases its lock. Detect a lost session
	// and cancel provider/stage I/O rather than silently proceeding unlocked.
	runCtx, cancel := context.WithCancelCause(ctx)
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-runCtx.Done():
				return
			case <-ticker.C:
				pingCtx, pingCancel := context.WithTimeout(runCtx, time.Second)
				err := conn.Ping(pingCtx)
				pingCancel()
				if err != nil {
					cancel(fmt.Errorf("deletion lock session lost: %w", err))
					return
				}
			}
		}
	}()
	err = fn(runCtx)
	close(stop)
	<-done
	if cause := context.Cause(runCtx); cause != nil && ctx.Err() == nil {
		err = cause
	}
	cancel(nil)
	return err
}

// PrepareCustomerDeletion accepts a human with exactly a GitHub identity and a
// customer ZITADEL identity, never a staff/service account or a mixed principal.
// The caller must independently verify ownership, all memberships and IdP org.
func (s *Store) PrepareCustomerDeletion(ctx context.Context, tenant, pid, issuer, actor string, validate ...func(*CustomerDeletion) error) (*CustomerDeletion, error) {
	if tenant == "" || !auth.ValidPrincipalID(pid) || issuer == "" || actor == "" {
		return nil, ErrInvalid
	}
	var result *CustomerDeletion
	existed := false
	load := func(tx pgx.Tx) error {
		existed = false
		if err := lockPrincipalTx(ctx, tx, pid); err != nil {
			return err
		}
		previous, err := scanCustomerDeletion(tx.QueryRow(ctx, `SELECT `+customerDeletionSelectColumns+` FROM customer_deletions WHERE tenant_name=$1 AND principal_id=$2`, tenant, pid))
		if err == nil {
			if previous.Cancelled {
				return ErrInvalid
			}
			existed = true
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
		d, err := customerDeletionIdentityTx(ctx, tx, tenant, pid, issuer, actor)
		if err != nil {
			return err
		}
		result = d
		return nil
	}
	key := "customer-deletion|" + tenant + "|" + pid
	if err := s.withTx(ctx, key, load); err != nil {
		return nil, customerDeletionStorageError(err)
	}
	approved := *result
	// Network/GitOps observations never hold a DB transaction or principal lock.
	for _, check := range validate {
		if err := check(&approved); err != nil {
			return nil, err
		}
	}
	err := s.withTx(ctx, key, func(tx pgx.Tx) error {
		if err := load(tx); err != nil {
			return err
		}
		if *result != approved {
			return fmt.Errorf("%w: customer identity changed during approval", ErrInvalid)
		}
		if existed {
			return nil
		}
		d := result
		_, err := tx.Exec(ctx, `INSERT INTO customer_deletions (`+customerDeletionColumns+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, d.Tenant, d.PrincipalID, d.GitHubID, d.Login, d.Issuer, d.Subject, d.Actor, d.Status)
		return err
	})
	return result, customerDeletionStorageError(err)
}

// CustomerTenantDeletionPending also fences administrator/MCP name reuse
// after resource removal, while identity/session cleanup is still running.
func (s *Store) CustomerTenantDeletionPending(ctx context.Context, tenant string) (bool, error) {
	var pending bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM customer_deletions WHERE tenant_name=$1 AND (status<>'complete' OR released_at IS NULL))`, tenant).Scan(&pending)
	return pending, err
}

// ReleaseCustomerDeletion records the final portal acknowledgment. Until it
// is durable, both GitHub registration and administrator name reuse stay frozen.
func (s *Store) ReleaseCustomerDeletion(ctx context.Context, tenant, pid string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE customer_deletions SET released_at=COALESCE(released_at,now()) WHERE tenant_name=$1 AND principal_id=$2 AND status='complete'`, tenant, pid)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrInvalid
	}
	return nil
}

func (s *Store) CustomerDeletionPending(ctx context.Context, githubID string) (bool, error) {
	var pending bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM customer_deletions WHERE github_id=$1 AND cancelled_at IS NULL AND (status<>'complete' OR released_at IS NULL))`, githubID).Scan(&pending)
	return pending, err
}

func (s *Store) CustomerSubjectDeleted(ctx context.Context, issuer, subject string) (bool, error) {
	var deleted bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM customer_deletions WHERE issuer=$1 AND subject=$2 AND cancelled_at IS NULL AND status IN ('prepared','deleting','complete'))`, issuer, subject).Scan(&deleted)
	return deleted, err
}

func (s *Store) CustomerPrincipalDeleted(ctx context.Context, pid string) (bool, error) {
	var deleted bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM customer_deletions WHERE principal_id=$1 AND cancelled_at IS NULL AND status IN ('prepared','deleting','complete'))`, pid).Scan(&deleted)
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
		if err := tx.QueryRow(ctx, `SELECT status FROM customer_deletions WHERE tenant_name=$1 AND principal_id=$2 AND cancelled_at IS NULL FOR UPDATE`, tenant, pid).Scan(&status); err != nil {
			return err
		}
		if status == "complete" {
			return nil
		}
		if status == "prepared" {
			approved, err := s.customerDeletionTx(ctx, tx, tenant, pid)
			if err != nil {
				return err
			}
			current, err := customerDeletionIdentityTx(ctx, tx, tenant, pid, approved.Issuer, approved.Actor)
			if err != nil {
				return err
			}
			if current.GitHubID != approved.GitHubID || current.Subject != approved.Subject || !strings.EqualFold(current.Login, approved.Login) {
				return fmt.Errorf("%w: approved customer identities changed before begin", ErrInvalid)
			}
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
		var status, login, githubID string
		if err := tx.QueryRow(ctx, `SELECT status,login,github_id FROM customer_deletions WHERE tenant_name=$1 AND principal_id=$2 FOR UPDATE`, tenant, pid).Scan(&status, &login, &githubID); err != nil {
			return err
		}
		if status == "complete" {
			return nil
		}
		if status != "deleting" {
			return ErrInvalid
		}
		// Older surface links were keyed by the verified GitHub login rather
		// than the immutable principal. Remove both forms before name reuse.
		// These tables belong to independently configured stores. Their absence
		// is supported (surface store disabled, or refresh store in another DB).
		// RevokeSessions has already revoked the configured refresh store.
		for _, cleanup := range []struct{ table, query string }{
			{"surface_identity_links", "DELETE FROM surface_identity_links WHERE principal=$1 OR lower(principal)=$2"},
			{"surface_identity_challenges", "DELETE FROM surface_identity_challenges WHERE principal=$1 OR lower(principal)=$2"},
			{"oauth_refresh_tokens", "DELETE FROM oauth_refresh_tokens WHERE principal_id=$1"},
		} {
			var present bool
			if err := tx.QueryRow(ctx, `SELECT to_regclass('public.'||$1) IS NOT NULL`, cleanup.table).Scan(&present); err != nil {
				return err
			}
			if !present {
				continue
			}
			args := []any{pid}
			if cleanup.table != "oauth_refresh_tokens" {
				args = append(args, "github:"+strings.ToLower(login))
			}
			if _, err := tx.Exec(ctx, cleanup.query, args...); err != nil {
				return err
			}
		}
		if err := signupLock(ctx, tx); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE signup_requests SET status='released',notification_pending=false WHERE (principal_id=$1 OR github_id=$2) AND status IN ('approved','claimed')`, pid, githubID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM external_identities WHERE principal_id=$1`, pid); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `DELETE FROM principals WHERE id=$1 AND status='disabled' AND kind='human'`, pid)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrInvalid
		}
		_, err = tx.Exec(ctx, `UPDATE customer_deletions SET status='complete',completed_at=now() WHERE tenant_name=$1 AND principal_id=$2`, tenant, pid)
		return err
	})
}

// CancelCustomerDeletion is called under the run lock, before begin only.
func (s *Store) CancelCustomerDeletion(ctx context.Context, tenant, pid string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE customer_deletions SET cancelled_at=COALESCE(cancelled_at,now()) WHERE tenant_name=$1 AND principal_id=$2 AND status='prepared'`, tenant, pid)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrInvalid
	}
	return nil
}

// FinishCustomerCancellation releases the name only after portal acknowledgment.
func (s *Store) FinishCustomerCancellation(ctx context.Context, tenant, pid string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM customer_deletions WHERE tenant_name=$1 AND principal_id=$2 AND status='prepared' AND cancelled_at IS NOT NULL`, tenant, pid)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrInvalid
	}
	return nil
}

func (s *Store) customerDeletionTx(ctx context.Context, tx pgx.Tx, tenant, pid string) (*CustomerDeletion, error) {
	return scanCustomerDeletion(tx.QueryRow(ctx, `SELECT `+customerDeletionSelectColumns+` FROM customer_deletions WHERE tenant_name=$1 AND principal_id=$2`, tenant, pid))
}

// Authentication identities are exactly GitHub + the customer issuer. Proven
// surface mirrors (live or revoked) are owned data to purge, not extra accounts.
func customerDeletionIdentityTx(ctx context.Context, tx pgx.Tx, tenant, pid, issuer, actor string) (*CustomerDeletion, error) {
	var hasSurface bool
	if err := tx.QueryRow(ctx, `SELECT to_regclass('public.surface_identity_links') IS NOT NULL`).Scan(&hasSurface); err != nil {
		return nil, err
	}
	query := `SELECT provider,issuer,subject,display,revoked_at IS NOT NULL,false FROM external_identities WHERE principal_id=$1`
	if hasSurface {
		query = `SELECT e.provider,e.issuer,e.subject,e.display,e.revoked_at IS NOT NULL,
   EXISTS(SELECT 1 FROM surface_identity_links l WHERE l.surface=e.provider AND l.external_id=e.subject AND
    (l.principal=e.principal_id OR EXISTS(SELECT 1 FROM external_identities g WHERE g.principal_id=e.principal_id AND g.provider='github' AND g.issuer='' AND g.revoked_at IS NULL AND lower(l.principal)='github:'||lower(g.display))))
   FROM external_identities e WHERE e.principal_id=$1`
	}
	rows, err := tx.Query(ctx, query, pid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	d := &CustomerDeletion{Tenant: tenant, PrincipalID: pid, Issuer: issuer, Actor: actor, Status: "prepared"}
	count, invalid := 0, false
	for rows.Next() {
		var provider, iss, sub, display string
		var revoked, mirror bool
		if err := rows.Scan(&provider, &iss, &sub, &display, &revoked, &mirror); err != nil {
			return nil, err
		}
		if mirror && iss == "" && !reservedProvider(provider) {
			continue
		}
		count++
		if revoked {
			invalid = true
			continue
		}
		switch {
		case provider == auth.ProviderGitHub && iss == "":
			d.GitHubID = sub
			d.Login = display
		case provider == "zitadel" && iss == issuer:
			d.Subject = sub
		default:
			invalid = true
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if invalid || count != 2 || d.GitHubID == "" || d.Subject == "" || strings.TrimSpace(d.Login) == "" {
		return nil, fmt.Errorf("%w: unrelated, revoked or unproven customer authentication identity", ErrInvalid)
	}
	return d, nil
}

func customerDeletionStorageError(err error) error {
	if err == nil || errors.Is(err, ErrInvalid) || errors.Is(err, ErrNotFound) || errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	var conflict *pgconn.PgError
	if errors.As(err, &conflict) && conflict.Code == "23505" {
		return fmt.Errorf("%w: another customer deletion is pending", ErrInvalid)
	}
	return fmt.Errorf("%w: customer deletion storage: %w", ErrUnresolved, err)
}
