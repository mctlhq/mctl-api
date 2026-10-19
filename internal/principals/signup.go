package principals

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Decisions and the global slot budget share a PostgreSQL transaction lock.
// KV is the immutable submission source, never the admission authority.
const signupSchema = `
CREATE TABLE IF NOT EXISTS signup_capacity (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton), slots integer NOT NULL DEFAULT 0 CHECK(slots>=0 AND slots<=1000),
 actor text NOT NULL DEFAULT '', reason text NOT NULL DEFAULT '', updated_at timestamptz NOT NULL DEFAULT now());
INSERT INTO signup_capacity(singleton) VALUES(true) ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS signup_requests (
 id uuid PRIMARY KEY, payload jsonb, created_at timestamptz NOT NULL,
 status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected','claimed','released')),
 github_id text, github_login text, actor text NOT NULL DEFAULT '', reason text NOT NULL DEFAULT '',
 decided_at timestamptz, expires_at timestamptz, tenant text, principal_id text,
 notification_pending boolean NOT NULL DEFAULT false, delivery_started_at timestamptz,
 delivery_lease uuid, delivery_leased_until timestamptz, delivery_id text);
CREATE TABLE IF NOT EXISTS signup_legacy_github(subject text PRIMARY KEY);
CREATE TABLE IF NOT EXISTS signup_admission_cutover(singleton boolean PRIMARY KEY CHECK(singleton),initialized_at timestamptz NOT NULL DEFAULT now());
WITH first_cutover AS (
 INSERT INTO signup_admission_cutover(singleton) VALUES(true) ON CONFLICT DO NOTHING RETURNING initialized_at
) INSERT INTO signup_legacy_github(subject)
 SELECT DISTINCT x.subject FROM external_identities x JOIN principals p ON p.id=x.principal_id CROSS JOIN first_cutover
 WHERE x.provider='github' AND x.revoked_at IS NULL AND p.status='active' AND p.kind='human' ON CONFLICT DO NOTHING;
CREATE UNIQUE INDEX IF NOT EXISTS signup_live_github ON signup_requests(github_id)
 WHERE status IN ('approved','claimed');
CREATE UNIQUE INDEX IF NOT EXISTS signup_claimed_tenant ON signup_requests(tenant) WHERE status='claimed';
`

var ErrSignupCapacity = errors.New("signup capacity exhausted")
var ErrSignupConflict = errors.New("signup decision or claim conflict")
var ErrSignupNotAllowed = errors.New("signup invitation required")

type SignupRequest struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"createdAt"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	GitHub    string    `json:"github"`
	Project   string    `json:"project"`
}
type SignupDecision struct {
	Request             SignupRequest `json:"request"`
	Status              string        `json:"status"`
	GitHubID            string        `json:"github_id"`
	GitHubLogin         string        `json:"github_login"`
	Actor               string        `json:"actor"`
	Reason              string        `json:"reason"`
	ExpiresAt           *time.Time    `json:"expires_at"`
	Tenant              string        `json:"tenant"`
	NotificationPending bool          `json:"notification_pending"`
	Lease               string        `json:"lease,omitempty"`
}
type SignupCapacity struct {
	Slots     int    `json:"slots"`
	Used      int    `json:"used"`
	Available int    `json:"available"`
	Actor     string `json:"actor"`
	Reason    string `json:"reason"`
}

const signupColumns = `id::text,payload,created_at,status,coalesce(github_id,''),coalesce(github_login,''),actor,reason,expires_at,coalesce(tenant,''),notification_pending`

func scanSignup(row pgx.Row) (SignupDecision, error) {
	var d SignupDecision
	var payload []byte
	err := row.Scan(&d.Request.ID, &payload, &d.Request.CreatedAt, &d.Status, &d.GitHubID, &d.GitHubLogin, &d.Actor, &d.Reason, &d.ExpiresAt, &d.Tenant, &d.NotificationPending)
	if err != nil {
		return d, err
	}
	if payload != nil {
		id, at := d.Request.ID, d.Request.CreatedAt
		if err := json.Unmarshal(payload, &d.Request); err != nil {
			return d, err
		}
		d.Request.ID = id
		d.Request.CreatedAt = at
	}
	return d, nil
}
func (s *Store) ImportSignup(ctx context.Context, r SignupRequest) error {
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	// A replay cannot replace the recipient or project of a saved request.
	tag, err := s.pool.Exec(ctx, `INSERT INTO signup_requests(id,payload,created_at) VALUES($1,$2,$3)
 ON CONFLICT(id) DO UPDATE SET id=excluded.id WHERE signup_requests.payload=excluded.payload`, r.ID, raw, r.CreatedAt)
	if err == nil && tag.RowsAffected() != 1 {
		return ErrSignupConflict
	}
	return err
}
func (s *Store) Signup(ctx context.Context, id string) (SignupDecision, error) {
	return scanSignup(s.pool.QueryRow(ctx, `SELECT `+signupColumns+` FROM signup_requests WHERE id=$1`, id))
}
func (s *Store) ListSignups(ctx context.Context) ([]SignupDecision, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+signupColumns+` FROM signup_requests WHERE payload IS NOT NULL ORDER BY created_at DESC LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []SignupDecision{}
	for rows.Next() {
		d, e := scanSignup(rows)
		if e != nil {
			return nil, e
		}
		result = append(result, d)
	}
	return result, rows.Err()
}
func signupLock(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('signup-admission-budget'))`)
	return err
}
func signupExpire(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `UPDATE signup_requests SET status='released',notification_pending=false WHERE status='approved' AND expires_at<=now()`)
	return err
}
func (s *Store) SignupCapacity(ctx context.Context) (SignupCapacity, error) {
	var c SignupCapacity
	err := s.pool.QueryRow(ctx, `SELECT slots,actor,reason,(SELECT count(*) FROM signup_requests WHERE status='claimed' OR (status='approved' AND expires_at>now())) FROM signup_capacity WHERE singleton=true`).Scan(&c.Slots, &c.Actor, &c.Reason, &c.Used)
	c.Available = max(0, c.Slots-c.Used)
	return c, err
}
func (s *Store) SetSignupCapacity(ctx context.Context, slots int, actor, reason string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := signupLock(ctx, tx); err != nil {
			return err
		}
		if err := signupExpire(ctx, tx); err != nil {
			return err
		}
		var used int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM signup_requests WHERE status IN ('approved','claimed')`).Scan(&used); err != nil {
			return err
		}
		if slots < used {
			return ErrSignupCapacity
		}
		_, err := tx.Exec(ctx, `UPDATE signup_capacity SET slots=$1,actor=$2,reason=$3,updated_at=now() WHERE singleton=true`, slots, actor, reason)
		return err
	})
}
func (s *Store) DecideSignup(ctx context.Context, id, status, githubID, login, actor, reason string) (SignupDecision, error) {
	var result SignupDecision
	if (status != "approved" && status != "rejected") || actor == "" || reason == "" || (status == "approved" && (githubID == "" || login == "")) {
		return result, ErrInvalid
	}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := signupLock(ctx, tx); err != nil {
			return err
		}
		if err := signupExpire(ctx, tx); err != nil {
			return err
		}
		current, err := scanSignup(tx.QueryRow(ctx, `SELECT `+signupColumns+` FROM signup_requests WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		if current.Status == status && (status == "rejected" || current.GitHubID == githubID) {
			result = current
			return nil
		}
		if current.Status != "pending" || current.Request.CreatedAt.Before(time.Now().Add(-90*24*time.Hour)) {
			return ErrSignupConflict
		}
		if status == "approved" {
			var slots, used int
			if err := tx.QueryRow(ctx, `SELECT slots,(SELECT count(*) FROM signup_requests WHERE status IN ('approved','claimed')) FROM signup_capacity WHERE singleton=true`).Scan(&slots, &used); err != nil {
				return err
			}
			if used >= slots {
				return ErrSignupCapacity
			}
			var duplicate bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM signup_requests WHERE github_id=$1 AND status IN ('approved','claimed'))`, githubID).Scan(&duplicate); err != nil {
				return err
			}
			if duplicate {
				return ErrSignupConflict
			}
		}
		result, err = scanSignup(tx.QueryRow(ctx, `UPDATE signup_requests SET status=$2,github_id=nullif($3,''),github_login=nullif($4,''),actor=$5,reason=$6,decided_at=now(),expires_at=CASE WHEN $2='approved' THEN now()+interval '7 days' ELSE NULL END,notification_pending=true WHERE id=$1 RETURNING `+signupColumns, id, status, githubID, login, actor, reason))
		return err
	})
	return result, err
}
func (s *Store) SignupAllowed(ctx context.Context, githubID string) (bool, error) {
	var allowed bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM signup_requests WHERE github_id=$1 AND (status='claimed' OR (status='approved' AND expires_at>now())))`, githubID).Scan(&allowed)
	return allowed, err
}

// ClaimSignup pins one reservation to one workspace before any provisioning.
// Ambiguous workflow submission keeps the claim; it is never freed by a timeout.
func (s *Store) SignupGrandfathered(ctx context.Context, githubID string) (bool, error) {
	var allowed bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM signup_legacy_github WHERE subject=$1)`, githubID).Scan(&allowed)
	return allowed, err
}
func (s *Store) ClaimSignup(ctx context.Context, githubID, tenant, pid string) error {
	return s.claimSignup(ctx, githubID, tenant, pid, false)
}

// Public mode still spends the same bounded durable budget; '*' never bypasses it.
func (s *Store) ClaimPublicSignup(ctx context.Context, githubID, tenant, pid string) error {
	return s.claimSignup(ctx, githubID, tenant, pid, true)
}
func (s *Store) claimSignup(ctx context.Context, githubID, tenant, pid string, public bool) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := lockPrincipalTx(ctx, tx, pid); err != nil {
			return err
		}
		var active bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM principals p JOIN external_identities x ON x.principal_id=p.id WHERE p.id=$1 AND p.status='active' AND p.kind='human' AND x.provider='github' AND x.subject=$2 AND x.revoked_at IS NULL)`, pid, githubID).Scan(&active); err != nil {
			return err
		}
		if !active {
			return ErrSignupNotAllowed
		}
		if err := signupLock(ctx, tx); err != nil {
			return err
		}
		if err := signupExpire(ctx, tx); err != nil {
			return err
		}
		var id, status, currentTenant, currentPID string
		err := tx.QueryRow(ctx, `SELECT id::text,status,coalesce(tenant,''),coalesce(principal_id,'') FROM signup_requests WHERE github_id=$1 AND status IN ('approved','claimed') FOR UPDATE`, githubID).Scan(&id, &status, &currentTenant, &currentPID)
		if errors.Is(err, pgx.ErrNoRows) && public {
			var slots, used int
			if err := tx.QueryRow(ctx, `SELECT slots,(SELECT count(*) FROM signup_requests WHERE status IN ('approved','claimed')) FROM signup_capacity WHERE singleton=true`).Scan(&slots, &used); err != nil {
				return err
			}
			if used >= slots {
				return ErrSignupCapacity
			}
			_, err = tx.Exec(ctx, `INSERT INTO signup_requests(id,created_at,status,github_id,actor,reason,decided_at,tenant,principal_id) VALUES($1,now(),'claimed',$2,$3,'Public signup admission',now(),$4,$3)`, uuid.NewString(), githubID, pid, tenant)
			return err
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrSignupNotAllowed
		}
		if err != nil {
			return err
		}
		if status == "claimed" {
			if currentTenant == tenant && currentPID == pid {
				return nil
			}
			return ErrSignupConflict
		}
		_, err = tx.Exec(ctx, `UPDATE signup_requests SET status='claimed',tenant=$2,principal_id=$3 WHERE id=$1`, id, tenant, pid)
		return err
	})
}

// Delivery leases serialize retries across API replicas. The provider key is
// stable per immutable decision; older uncertain attempts need reconciliation.
func (s *Store) LeaseSignupDelivery(ctx context.Context, lease string) (SignupDecision, error) {
	d, err := scanSignup(s.pool.QueryRow(ctx, `UPDATE signup_requests SET delivery_lease=$1,delivery_leased_until=now()+interval '2 minutes',delivery_started_at=coalesce(delivery_started_at,now()) WHERE id=(SELECT id FROM signup_requests WHERE notification_pending AND (status IN ('claimed','rejected') OR (status='approved' AND expires_at>now())) AND payload IS NOT NULL AND (delivery_leased_until IS NULL OR delivery_leased_until<now()) AND (delivery_started_at IS NULL OR delivery_started_at>now()-interval '23 hours') ORDER BY decided_at FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING `+signupColumns, lease))
	d.Lease = lease
	return d, err
}
func (s *Store) AckSignupDelivery(ctx context.Context, id, lease, deliveryID string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE signup_requests SET notification_pending=false,delivery_id=$3,delivery_lease=NULL,delivery_leased_until=NULL WHERE id=$1 AND delivery_lease=$2 AND delivery_leased_until>now()`, id, lease, deliveryID)
	if err == nil && tag.RowsAffected() != 1 {
		return fmt.Errorf("signup delivery lease lost")
	}
	return err
}
func (s *Store) CleanupSignupPII(ctx context.Context) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := signupLock(ctx, tx); err != nil {
			return err
		}
		if err := signupExpire(ctx, tx); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE signup_requests SET payload=NULL,reason='',notification_pending=false WHERE payload IS NOT NULL AND created_at<now()-interval '90 days'`)
		return err
	})
}

func (s *Store) ReleaseSignupClaim(ctx context.Context, pid string) error {
	_, err := s.pool.Exec(ctx, `UPDATE signup_requests SET status='released',notification_pending=false WHERE principal_id=$1 AND status='claimed'`, pid)
	return err
}
