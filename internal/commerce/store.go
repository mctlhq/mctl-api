// Copyright 2025 MCTL Authors
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

package commerce

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Deadlines (ADR 020 sec. 11).
const (
	DefaultReconciliationWindow = 24 * time.Hour
)

// commerceSchema is applied on every start, like usageSchema. Everything is
// additive and sits beside the usage ledger, never inside it (ADR 020
// sec. 14). No table stores arguments, results or payment proofs.
const commerceSchema = `
CREATE TABLE IF NOT EXISTS commerce_terms (
    terms_id          TEXT        NOT NULL,
    terms_version     BIGINT      NOT NULL,
    capability_id     TEXT        NOT NULL,
    input_schema_hash TEXT        NOT NULL,
    provider_id       TEXT        NOT NULL,
    price_mode        TEXT        NOT NULL,
    meter             TEXT        NOT NULL,
    currency          TEXT        NOT NULL,
    amount_minor      BIGINT      NOT NULL CHECK (amount_minor >= 0),
    funds_mode        TEXT        NOT NULL,
    quote_ttl_seconds INTEGER     NOT NULL,
    effective_from    TIMESTAMPTZ NOT NULL,
    retired_at        TIMESTAMPTZ,
    published_by      TEXT        NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (terms_id, terms_version)
);
CREATE UNIQUE INDEX IF NOT EXISTS commerce_terms_capability_version
    ON commerce_terms (capability_id, terms_version);

CREATE TABLE IF NOT EXISTS commerce_quotes (
    quote_id             TEXT        PRIMARY KEY,
    terms_id             TEXT        NOT NULL,
    terms_version        BIGINT      NOT NULL,
    capability_id        TEXT        NOT NULL,
    input_schema_hash    TEXT        NOT NULL,
    tenant_id            TEXT        NOT NULL,
    principal_id         TEXT        NOT NULL,
    subject_principal_id TEXT        NOT NULL,
    delegation_grant_id  TEXT        NOT NULL DEFAULT '',
    payer_account_id     TEXT        NOT NULL,
    execution_id         TEXT        NOT NULL,
    args_digest          TEXT        NOT NULL,
    price_mode           TEXT        NOT NULL,
    currency             TEXT        NOT NULL,
    amount_minor         BIGINT      NOT NULL CHECK (amount_minor >= 0),
    funds_mode           TEXT        NOT NULL,
    expires_at           TIMESTAMPTZ NOT NULL,
    quote_digest         TEXT        NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (terms_id, terms_version) REFERENCES commerce_terms (terms_id, terms_version)
);
CREATE INDEX IF NOT EXISTS commerce_quotes_tenant_created
    ON commerce_quotes (tenant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS commerce_invocations (
    invocation_id           TEXT        PRIMARY KEY,
    quote_id                TEXT        NOT NULL UNIQUE REFERENCES commerce_quotes (quote_id),
    quote_digest            TEXT        NOT NULL,
    quote_expires_at        TIMESTAMPTZ NOT NULL,
    terms_id                TEXT        NOT NULL,
    terms_version           BIGINT      NOT NULL,
    capability_id           TEXT        NOT NULL,
    provider_id             TEXT        NOT NULL,
    tenant_id               TEXT        NOT NULL,
    principal_id            TEXT        NOT NULL,
    subject_principal_id    TEXT        NOT NULL,
    delegation_grant_id     TEXT        NOT NULL DEFAULT '',
    payer_account_id        TEXT        NOT NULL,
    execution_id            TEXT        NOT NULL,
    idempotency_key         TEXT        NOT NULL,
    args_digest             TEXT        NOT NULL,
    price_mode              TEXT        NOT NULL,
    currency                TEXT        NOT NULL,
    amount_minor            BIGINT      NOT NULL CHECK (amount_minor >= 0),
    funds_mode              TEXT        NOT NULL,
    phase                   TEXT        NOT NULL,
    execution_outcome       TEXT        NOT NULL,
    usage_quantity          BIGINT,
    charge_status           TEXT        NOT NULL,
    payment_status          TEXT        NOT NULL,
    settlement_status       TEXT        NOT NULL,
    reason_code             TEXT        NOT NULL DEFAULT '',
    approval_id             TEXT        NOT NULL DEFAULT '',
    reservation_deadline    TIMESTAMPTZ,
    reconciliation_deadline TIMESTAMPTZ NOT NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    finalized_at            TIMESTAMPTZ,
    version                 BIGINT      NOT NULL DEFAULT 1,
    UNIQUE (tenant_id, principal_id, idempotency_key)
);
CREATE INDEX IF NOT EXISTS commerce_invocations_tenant_created
    ON commerce_invocations (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS commerce_invocations_open
    ON commerce_invocations (reconciliation_deadline)
    WHERE phase NOT IN ('refused', 'released', 'finalized');

-- C4 (mctl-agents#619): the dispatch fence and the approval binding.
-- dispatch_deadline is written once, by the reserved -> dispatching edge, and
-- every signed invocation authorization for the row carries exactly it, so a
-- second dispatcher can only ever present the same authorization and never
-- a later deadline. An approval is consumed by one invocation (ADR 020
-- sec. 8): the partial unique index makes a second row in the tenant naming
-- the same approval impossible, which is what lets the gateway read
-- "consumed, and this invocation carries it" as "consumed for this
-- invocation". It is scoped by tenant because approvals are tenant
-- resources and approval_id is caller input: a global index would let one
-- tenant squat another tenant's approval id and learn whether it exists.
-- A database that already holds a duplicate fails this statement and with it
-- the store, so every commerce route answers 503: deliberate, because
-- accepting paid calls without the binding is the worse failure.
ALTER TABLE commerce_invocations ADD COLUMN IF NOT EXISTS dispatch_deadline TIMESTAMPTZ;
CREATE UNIQUE INDEX IF NOT EXISTS commerce_invocations_tenant_approval
    ON commerce_invocations (tenant_id, approval_id) WHERE approval_id <> '';

-- The vocabulary CHECKs are added by name outside CREATE TABLE so that a
-- table created by an earlier build of this package gets them too:
-- CREATE TABLE IF NOT EXISTS is a no-op once the table exists, and the second
-- line of defence behind TransitionInput.validate must hold wherever the
-- table came from. The pg_constraint test keeps the common path cheap and the
-- duplicate_object handler covers two processes applying the schema at once.
DO $$
DECLARE c RECORD;
BEGIN
    FOR c IN SELECT * FROM (VALUES
        ('commerce_invocations_phase_check',
         $c$phase IN ('accepted','refused','reserved','dispatching','dispatched','outcome_unknown','released','finalized')$c$),
        ('commerce_invocations_execution_outcome_check',
         $c$execution_outcome IN ('not_dispatched','succeeded','failed','unknown')$c$),
        ('commerce_invocations_usage_quantity_check',
         $c$usage_quantity IS NULL OR usage_quantity >= 0$c$),
        ('commerce_invocations_charge_status_check',
         $c$charge_status IN ('none','reserved','captured','released')$c$),
        ('commerce_invocations_payment_status_check',
         $c$payment_status IN ('none','not_required','authorized','denied','captured','voided','unknown')$c$),
        ('commerce_invocations_settlement_status_check',
         $c$settlement_status IN ('not_applicable','pending','settled','failed')$c$)
    ) AS t(name, expr)
    LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = c.name) THEN
            BEGIN
                EXECUTE format('ALTER TABLE commerce_invocations ADD CONSTRAINT %I CHECK (%s)', c.name, c.expr);
            EXCEPTION WHEN duplicate_object THEN
                -- Two processes cold-started together; the other one won.
                NULL;
            END;
        END IF;
    END LOOP;
END $$;

CREATE TABLE IF NOT EXISTS commerce_invocation_transitions (
    seq           BIGSERIAL   PRIMARY KEY,
    invocation_id TEXT        NOT NULL REFERENCES commerce_invocations (invocation_id),
    from_phase    TEXT        NOT NULL,
    to_phase      TEXT        NOT NULL,
    reason_code   TEXT        NOT NULL DEFAULT '',
    actor         TEXT        NOT NULL,
    note          TEXT        NOT NULL DEFAULT '',
    recorded_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS commerce_invocation_transitions_invocation
    ON commerce_invocation_transitions (invocation_id, seq);

-- C3 (mctl-api#548): budgets, their change history, reservations and the
-- payment operations the simulated adapter records. A budget is a limit;
-- no table holds a balance that could be topped up.
CREATE TABLE IF NOT EXISTS commerce_budgets (
    tenant_id             TEXT        NOT NULL,
    payer_account_id      TEXT        NOT NULL,
    currency              TEXT        NOT NULL,
    funds_mode            TEXT        NOT NULL CHECK (funds_mode = 'simulated'),
    monthly_limit_minor   BIGINT      NOT NULL CHECK (monthly_limit_minor >= 0),
    per_request_max_minor BIGINT      NOT NULL CHECK (per_request_max_minor >= 1),
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    version               BIGINT      NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, payer_account_id)
);

CREATE TABLE IF NOT EXISTS commerce_budget_changes (
    seq                       BIGSERIAL   PRIMARY KEY,
    tenant_id                 TEXT        NOT NULL,
    payer_account_id          TEXT        NOT NULL,
    actor                     TEXT        NOT NULL,
    reason                    TEXT        NOT NULL,
    old_currency              TEXT,
    old_monthly_limit_minor   BIGINT,
    old_per_request_max_minor BIGINT,
    new_currency              TEXT        NOT NULL,
    new_monthly_limit_minor   BIGINT      NOT NULL,
    new_per_request_max_minor BIGINT      NOT NULL,
    recorded_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS commerce_budget_changes_account
    ON commerce_budget_changes (tenant_id, payer_account_id, seq);

CREATE TABLE IF NOT EXISTS commerce_reservations (
    reservation_id   TEXT        PRIMARY KEY,
    invocation_id    TEXT        NOT NULL UNIQUE REFERENCES commerce_invocations (invocation_id),
    tenant_id        TEXT        NOT NULL,
    payer_account_id TEXT        NOT NULL,
    period           TEXT        NOT NULL,
    currency         TEXT        NOT NULL,
    amount_minor     BIGINT      NOT NULL CHECK (amount_minor >= 0),
    status           TEXT        NOT NULL CHECK (status IN ('held', 'captured', 'released')),
    authorization_id TEXT        NOT NULL DEFAULT '',
    capture_id       TEXT        NOT NULL DEFAULT '',
    deadline         TIMESTAMPTZ NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS commerce_reservations_account
    ON commerce_reservations (tenant_id, payer_account_id, status, period);

CREATE TABLE IF NOT EXISTS commerce_payment_operations (
    op_key            TEXT        PRIMARY KEY,
    invocation_id     TEXT        NOT NULL,
    operation         TEXT        NOT NULL CHECK (operation IN ('authorize', 'capture', 'void')),
    tenant_id         TEXT        NOT NULL,
    payer_account_id  TEXT        NOT NULL,
    currency          TEXT        NOT NULL,
    amount_minor      BIGINT      NOT NULL CHECK (amount_minor >= 0),
    funds_mode        TEXT        NOT NULL,
    quote_digest      TEXT        NOT NULL DEFAULT '',
    authorization_id  TEXT        NOT NULL DEFAULT '',
    result            TEXT        NOT NULL CHECK (result IN ('authorized', 'denied', 'captured', 'voided', 'failed', 'unknown')),
    result_id         TEXT        NOT NULL DEFAULT '',
    reason            TEXT        NOT NULL DEFAULT '',
    settlement_status TEXT        NOT NULL,
    recorded_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS commerce_payment_operations_authorization
    ON commerce_payment_operations (result_id) WHERE operation = 'authorize';

CREATE TABLE IF NOT EXISTS commerce_entitlements (
    entitlement_id   TEXT        PRIMARY KEY,
    tenant_id        TEXT        NOT NULL,
    capability_id    TEXT        NOT NULL,
    total_units      BIGINT      NOT NULL CHECK (total_units > 0),
    remaining_units  BIGINT      NOT NULL CHECK (remaining_units >= 0),
    reserved_units   BIGINT      NOT NULL DEFAULT 0 CHECK (reserved_units >= 0),
    invoice_ref      TEXT        NOT NULL,
    payment_status   TEXT        NOT NULL,
    granted_by       TEXT        NOT NULL,
    reason           TEXT        NOT NULL DEFAULT '',
    expires_at       TIMESTAMPTZ NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS commerce_entitlements_tenant_cap
    ON commerce_entitlements (tenant_id, capability_id);
CREATE UNIQUE INDEX IF NOT EXISTS commerce_entitlements_invoice
    ON commerce_entitlements (tenant_id, invoice_ref);
ALTER TABLE commerce_entitlements ADD COLUMN IF NOT EXISTS granted_by TEXT NOT NULL DEFAULT '';
ALTER TABLE commerce_entitlements ADD COLUMN IF NOT EXISTS reason TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS commerce_entitlement_allocations (
    allocation_id   TEXT        PRIMARY KEY,
    entitlement_id  TEXT        NOT NULL REFERENCES commerce_entitlements (entitlement_id),
    invocation_id   TEXT        NOT NULL REFERENCES commerce_invocations (invocation_id),
    units           BIGINT      NOT NULL CHECK (units > 0),
    state           TEXT        NOT NULL CHECK (state IN ('held', 'captured', 'released')),
    recorded_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS commerce_entitlement_allocations_inv
    ON commerce_entitlement_allocations (invocation_id);
`

// Store is the Postgres-backed commerce ledger.
type Store struct {
	pool *pgxpool.Pool
	now  func() time.Time
	auth PaymentAuthorizer
	// signer signs dispatch authorizations (dispatch.go); nil disables
	// dispatch. Atomic so installing it cannot race a request in flight.
	signer atomic.Pointer[DispatchSigner]
}

// NewStore connects, applies the schema and returns the store with the
// simulated payment adapter installed.
func NewStore(ctx context.Context, connStr string) (*Store, error) {
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		return nil, fmt.Errorf("commerce: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("commerce: ping: %w", err)
	}
	if _, err := pool.Exec(ctx, commerceSchema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("commerce: schema: %w", err)
	}
	s := &Store{pool: pool, now: func() time.Time { return time.Now().UTC() }}
	// The adapter reads the store clock through the closure, so a test
	// that moves s.now moves the adapter too.
	if err := s.UseAuthorizer(SimulatedAuthorizer{now: func() time.Time { return s.now() }}); err != nil {
		pool.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the pool.
func (s *Store) Close() {
	if s != nil && s.pool != nil {
		s.pool.Close()
	}
}

func (s *Store) withTx(ctx context.Context, lockKey string, fn func(pgx.Tx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("commerce: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op once Commit has succeeded
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, lockKey); err != nil {
		return fmt.Errorf("commerce: acquire lock: %w", err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commerce: commit: %w", err)
	}
	return nil
}

// newULID is Crockford base32 of 48 bits of milliseconds and 80 random
// bits, the same shape internal/principals mints. It is copied rather than
// imported so this package does not depend on the principals store.
func newULID(t time.Time) (string, error) {
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	var raw [16]byte
	// 48 bits of milliseconds, big-endian, in raw[0:6]; the shift leaves
	// raw[6:8] zero for the random tail to overwrite.
	binary.BigEndian.PutUint64(raw[0:8], uint64(t.UnixMilli())<<16) //nolint:gosec // UnixMilli is positive for every date this runs on
	if _, err := rand.Read(raw[6:]); err != nil {
		return "", fmt.Errorf("commerce: crypto/rand: %w", err)
	}
	var out [26]byte
	// Encode 128 bits as 26 base32 characters, most significant first,
	// with the leading two bits of the first character zero.
	var acc uint64
	bits := 0
	pos := 25
	for i := 15; i >= 0; i-- {
		acc |= uint64(raw[i]) << bits
		bits += 8
		for bits >= 5 && pos >= 0 {
			out[pos] = alphabet[acc&31]
			acc >>= 5
			bits -= 5
			pos--
		}
	}
	for pos >= 0 {
		out[pos] = alphabet[acc&31]
		acc >>= 5
		pos--
	}
	return string(out[:]), nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// uniqueViolationOn reports a unique violation of one named constraint or
// index, so two different uniqueness rules on one insert keep their own
// answers.
func uniqueViolationOn(err error, constraint string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == constraint
}

// ---- terms --------------------------------------------------------------

const termsColumns = `terms_id, terms_version, capability_id, input_schema_hash, provider_id,
	price_mode, meter, currency, amount_minor, funds_mode, quote_ttl_seconds,
	effective_from, retired_at, published_by, created_at`

func scanTerms(row pgx.Row) (*Terms, error) {
	var t Terms
	if err := row.Scan(&t.TermsID, &t.TermsVersion, &t.CapabilityID, &t.InputSchemaHash, &t.ProviderID,
		&t.PriceMode, &t.Meter, &t.Price.Currency, &t.Price.AmountMinor, &t.FundsMode, &t.QuoteTTLSeconds,
		&t.EffectiveFrom, &t.RetiredAt, &t.PublishedBy, &t.CreatedAt); err != nil {
		return nil, err
	}
	t.SchemaVersion = SchemaVersion
	return &t, nil
}

// PublishTerms stores the next immutable version of a capability's terms
// (ADR 020 sec. 4). The first publication for a capability mints the
// terms_id; later ones must name it. Earlier versions are left in place and
// keep resolving for quotes already minted against them.
func (s *Store) PublishTerms(ctx context.Context, in PublishTermsInput) (*Terms, error) {
	if err := in.validate(); err != nil {
		return nil, err
	}
	var out *Terms
	err := s.withTx(ctx, "commerce:terms:"+in.CapabilityID, func(tx pgx.Tx) error {
		var existingID string
		var maxVersion int64
		err := tx.QueryRow(ctx, `SELECT terms_id, max(terms_version) FROM commerce_terms
			WHERE capability_id = $1 GROUP BY terms_id`, in.CapabilityID).Scan(&existingID, &maxVersion)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			if in.TermsID == "" {
				id, err := newULID(s.now())
				if err != nil {
					return err
				}
				in.TermsID = TermsIDPrefix + id
			} else {
				var n int
				if err := tx.QueryRow(ctx, `SELECT count(*) FROM commerce_terms WHERE terms_id = $1`, in.TermsID).Scan(&n); err != nil {
					return fmt.Errorf("commerce: check terms id: %w", err)
				}
				if n > 0 {
					return invalid("terms_id %s belongs to another capability", in.TermsID)
				}
			}
		case err != nil:
			return fmt.Errorf("commerce: current terms: %w", err)
		default:
			if in.TermsID == "" {
				in.TermsID = existingID
			} else if in.TermsID != existingID {
				return invalid("capability %s already has terms %s", in.CapabilityID, existingID)
			}
		}
		row := tx.QueryRow(ctx, `INSERT INTO commerce_terms (`+termsColumns+`)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NULL, $13, $14)
			RETURNING `+termsColumns,
			in.TermsID, maxVersion+1, in.CapabilityID, in.InputSchemaHash, in.ProviderID,
			in.PriceMode, MeterInvocation, in.Price.Currency, in.Price.AmountMinor, in.FundsMode,
			in.QuoteTTLSeconds, in.EffectiveFrom.UTC(), in.PublishedBy, s.now())
		t, err := scanTerms(row)
		if err != nil {
			return fmt.Errorf("commerce: insert terms: %w", err)
		}
		out = t
		return nil
	})
	return out, err
}

// RetireTerms marks one version retired. A retired version no longer
// mints quotes and makes quotes minted against it stale.
func (s *Store) RetireTerms(ctx context.Context, termsID string, version int64) (*Terms, error) {
	row := s.pool.QueryRow(ctx, `UPDATE commerce_terms SET retired_at = $3
		WHERE terms_id = $1 AND terms_version = $2 AND retired_at IS NULL
		RETURNING `+termsColumns, termsID, version, s.now())
	t, err := scanTerms(row)
	if errors.Is(err, pgx.ErrNoRows) {
		// Nothing changed: either the version never existed or it was
		// already retired. Tell the two apart so a double retire does not
		// read as "never existed".
		if _, gerr := s.getTerms(ctx, s.pool, termsID, version); gerr != nil {
			return nil, gerr
		}
		return nil, ErrTermsRetired
	}
	if err != nil {
		return nil, fmt.Errorf("commerce: retire terms: %w", err)
	}
	return t, nil
}

// GetTerms returns one exact version.
func (s *Store) GetTerms(ctx context.Context, termsID string, version int64) (*Terms, error) {
	return s.getTerms(ctx, s.pool, termsID, version)
}

type querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

func (s *Store) getTerms(ctx context.Context, q querier, termsID string, version int64) (*Terms, error) {
	t, err := scanTerms(q.QueryRow(ctx, `SELECT `+termsColumns+` FROM commerce_terms
		WHERE terms_id = $1 AND terms_version = $2`, termsID, version))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrTermsVersionMissing
	}
	if err != nil {
		return nil, fmt.Errorf("commerce: get terms: %w", err)
	}
	return t, nil
}

// CurrentTerms resolves the version in force for a capability and schema
// hash: the highest non-retired version whose effective_from has passed.
// A capability with no such version is unknown, which is not free (ADR 020
// sec. 12).
func (s *Store) CurrentTerms(ctx context.Context, capabilityID, inputSchemaHash string) (*Terms, error) {
	return s.currentTerms(ctx, s.pool, capabilityID, inputSchemaHash, s.now())
}

func (s *Store) currentTerms(ctx context.Context, q querier, capabilityID, inputSchemaHash string, now time.Time) (*Terms, error) {
	t, err := scanTerms(q.QueryRow(ctx, `SELECT `+termsColumns+` FROM commerce_terms
		WHERE capability_id = $1 AND input_schema_hash = $2 AND retired_at IS NULL AND effective_from <= $3
		ORDER BY terms_version DESC LIMIT 1`, capabilityID, inputSchemaHash, now))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrTermsNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("commerce: current terms: %w", err)
	}
	return t, nil
}

// ListTerms returns every version for a capability, newest first.
func (s *Store) ListTerms(ctx context.Context, capabilityID string) ([]Terms, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+termsColumns+` FROM commerce_terms
		WHERE capability_id = $1 ORDER BY terms_version DESC`, capabilityID)
	if err != nil {
		return nil, fmt.Errorf("commerce: list terms: %w", err)
	}
	defer rows.Close()
	out := []Terms{}
	for rows.Next() {
		t, err := scanTerms(rows)
		if err != nil {
			return nil, fmt.Errorf("commerce: scan terms: %w", err)
		}
		out = append(out, *t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("commerce: list terms: %w", err)
	}
	return out, nil
}

// ---- quotes -------------------------------------------------------------

const quoteColumns = `quote_id, terms_id, terms_version, capability_id, input_schema_hash,
	tenant_id, principal_id, subject_principal_id, delegation_grant_id, payer_account_id, execution_id,
	args_digest, price_mode, currency, amount_minor, funds_mode, expires_at, quote_digest, created_at`

func scanQuote(row pgx.Row) (*Quote, error) {
	var q Quote
	if err := row.Scan(&q.QuoteID, &q.TermsID, &q.TermsVersion, &q.CapabilityID, &q.InputSchemaHash,
		&q.TenantID, &q.PrincipalID, &q.SubjectPrincipalID, &q.DelegationGrantID, &q.PayerAccountID, &q.ExecutionID,
		&q.ArgsDigest, &q.PriceMode, &q.Price.Currency, &q.Price.AmountMinor, &q.FundsMode, &q.ExpiresAt,
		&q.QuoteDigest, &q.CreatedAt); err != nil {
		return nil, err
	}
	q.SchemaVersion = SchemaVersion
	return &q, nil
}

// MintQuote prices one call at the current terms for the resolved
// identities (ADR 020 sec. 5). The quote is immutable; a changed argument
// digest or payer is a new quote.
func (s *Store) MintQuote(ctx context.Context, in MintQuoteInput) (*Quote, error) {
	if err := in.validate(); err != nil {
		return nil, err
	}
	now := s.now()
	t, err := s.currentTerms(ctx, s.pool, in.CapabilityID, in.InputSchemaHash, now)
	if err != nil {
		return nil, err
	}
	if err := checkFundsMode(t.FundsMode); err != nil {
		return nil, err
	}
	quoteID, err := newULID(now)
	if err != nil {
		return nil, err
	}
	q := Quote{
		SchemaVersion:   SchemaVersion,
		QuoteID:         QuoteIDPrefix + quoteID,
		TermsID:         t.TermsID,
		TermsVersion:    t.TermsVersion,
		CapabilityID:    t.CapabilityID,
		InputSchemaHash: t.InputSchemaHash,
		Identities:      in.Identities,
		ArgsDigest:      in.ArgsDigest,
		PriceMode:       t.PriceMode,
		Price:           t.Price,
		FundsMode:       t.FundsMode,
		ExpiresAt:       now.Add(time.Duration(t.QuoteTTLSeconds) * time.Second).Truncate(time.Second),
		CreatedAt:       now,
	}
	q.QuoteDigest = QuoteDigest(q)
	row := s.pool.QueryRow(ctx, `INSERT INTO commerce_quotes (`+quoteColumns+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
		RETURNING `+quoteColumns,
		q.QuoteID, q.TermsID, q.TermsVersion, q.CapabilityID, q.InputSchemaHash,
		q.TenantID, q.PrincipalID, q.SubjectPrincipalID, q.DelegationGrantID, q.PayerAccountID, q.ExecutionID,
		q.ArgsDigest, q.PriceMode, q.Price.Currency, q.Price.AmountMinor, q.FundsMode, q.ExpiresAt,
		q.QuoteDigest, q.CreatedAt)
	stored, err := scanQuote(row)
	if err != nil {
		return nil, fmt.Errorf("commerce: insert quote: %w", err)
	}
	return stored, nil
}

// GetQuote returns a quote visible to one tenant. Another tenant's quote
// is not found (ADR 020 sec. 12).
func (s *Store) GetQuote(ctx context.Context, tenantID, quoteID string) (*Quote, error) {
	q, err := scanQuote(s.pool.QueryRow(ctx, `SELECT `+quoteColumns+` FROM commerce_quotes
		WHERE quote_id = $1 AND tenant_id = $2`, quoteID, tenantID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrQuoteNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("commerce: get quote: %w", err)
	}
	return q, nil
}

// ---- invocations --------------------------------------------------------

const invocationColumns = `invocation_id, quote_id, quote_digest, quote_expires_at, terms_id, terms_version,
	capability_id, provider_id, tenant_id, principal_id, subject_principal_id, delegation_grant_id,
	payer_account_id, execution_id, idempotency_key, args_digest, price_mode, currency, amount_minor,
	funds_mode, phase, execution_outcome, usage_quantity, charge_status, payment_status, settlement_status,
	reason_code, approval_id, reservation_deadline, reconciliation_deadline, created_at, updated_at,
	finalized_at, version, dispatch_deadline`

func scanInvocation(row pgx.Row) (*Invocation, error) {
	var v Invocation
	if err := row.Scan(&v.InvocationID, &v.QuoteID, &v.QuoteDigest, &v.QuoteExpiresAt, &v.TermsID, &v.TermsVersion,
		&v.CapabilityID, &v.ProviderID, &v.TenantID, &v.PrincipalID, &v.SubjectPrincipalID, &v.DelegationGrantID,
		&v.PayerAccountID, &v.ExecutionID, &v.IdempotencyKey, &v.ArgsDigest, &v.PriceMode, &v.Price.Currency,
		&v.Price.AmountMinor, &v.FundsMode, &v.Phase, &v.ExecutionOutcome, &v.UsageQuantity, &v.ChargeStatus,
		&v.PaymentStatus, &v.SettlementStatus, &v.ReasonCode, &v.ApprovalID, &v.ReservationDeadline,
		&v.ReconciliationDeadline, &v.CreatedAt, &v.UpdatedAt, &v.FinalizedAt, &v.Version, &v.DispatchDeadline); err != nil {
		return nil, err
	}
	v.SchemaVersion = SchemaVersion
	v.ProviderOpKey = ProviderOperationKey(v.InvocationID)
	return &v, nil
}

// AcceptResult is what AcceptInvocation returns: the row, and whether it
// already existed for the same idempotency key and quote digest.
type AcceptResult struct {
	Invocation *Invocation
	Replayed   bool
}

// AcceptInvocation is step 6 of ADR 020 sec. 7. Under the idempotency scope
// (tenant, principal, key) it returns the existing invocation when the
// quote digest matches, refuses with ErrIdempotencyConflict when it does
// not, and otherwise verifies the quote against the server-resolved
// identities and the terms in force and stores the row in phase accepted.
// Nothing is reserved here; that is C3.
func (s *Store) AcceptInvocation(ctx context.Context, in AcceptInvocationInput) (*AcceptResult, error) {
	if err := in.validate(); err != nil {
		return nil, err
	}
	id := in.Identities
	// The lock key is length-prefixed so (a, bc, d) and (ab, c, d) cannot
	// share a lock; hashtext() takes text, so no NUL separator.
	lockKey := lengthPrefixed("commerce-idem/v1", [][2]string{
		{"tenant_id", id.TenantID}, {"principal_id", id.PrincipalID}, {"idempotency_key", in.IdempotencyKey}})
	var res AcceptResult
	err := s.withTx(ctx, lockKey, func(tx pgx.Tx) error {
		existing, err := scanInvocation(tx.QueryRow(ctx, `SELECT `+invocationColumns+` FROM commerce_invocations
			WHERE tenant_id = $1 AND principal_id = $2 AND idempotency_key = $3`,
			id.TenantID, id.PrincipalID, in.IdempotencyKey))
		switch {
		case err == nil:
			if existing.QuoteDigest != in.QuoteDigest {
				return ErrIdempotencyConflict
			}
			res = AcceptResult{Invocation: existing, Replayed: true}
			return nil
		case !errors.Is(err, pgx.ErrNoRows):
			return fmt.Errorf("commerce: idempotency lookup: %w", err)
		}

		q, err := scanQuote(tx.QueryRow(ctx, `SELECT `+quoteColumns+` FROM commerce_quotes
			WHERE quote_id = $1 AND tenant_id = $2`, in.QuoteID, id.TenantID))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrQuoteNotFound
		}
		if err != nil {
			return fmt.Errorf("commerce: load quote: %w", err)
		}
		// The stored digest is recomputed, so a row edited behind the API
		// cannot be accepted, and the client's copy must match it.
		if QuoteDigest(*q) != q.QuoteDigest || q.QuoteDigest != in.QuoteDigest {
			return fmt.Errorf("%w: quote_digest", ErrQuoteMismatch)
		}
		if q.Identities != id {
			return fmt.Errorf("%w: identities", ErrQuoteMismatch)
		}
		if q.ArgsDigest != in.ArgsDigest {
			return fmt.Errorf("%w: args_digest", ErrQuoteMismatch)
		}
		now := s.now()
		if !now.Before(q.ExpiresAt) {
			return ErrQuoteExpired
		}
		if err := checkFundsMode(q.FundsMode); err != nil {
			return err
		}
		t, err := s.getTerms(ctx, tx, q.TermsID, q.TermsVersion)
		if err != nil {
			return err
		}
		if t.RetiredAt != nil {
			return ErrQuoteStale
		}
		current, err := s.currentTerms(ctx, tx, q.CapabilityID, q.InputSchemaHash, now)
		if err != nil {
			return err
		}
		if current.TermsVersion != q.TermsVersion {
			return ErrQuoteStale
		}
		if in.TermsBinding != "" && in.TermsBinding != TermsBinding(*t, id.TenantID, id.PayerAccountID) {
			return fmt.Errorf("%w: terms_binding", ErrQuoteMismatch)
		}

		paymentStatus := PaymentNone
		if q.PriceMode == PriceModeFree {
			paymentStatus = PaymentNotRequired
		}
		invID, err := newULID(now)
		if err != nil {
			return err
		}
		v := Invocation{
			InvocationID:           InvocationIDPrefix + invID,
			QuoteID:                q.QuoteID,
			QuoteDigest:            q.QuoteDigest,
			QuoteExpiresAt:         q.ExpiresAt,
			TermsID:                q.TermsID,
			TermsVersion:           q.TermsVersion,
			CapabilityID:           q.CapabilityID,
			ProviderID:             t.ProviderID,
			Identities:             id,
			IdempotencyKey:         in.IdempotencyKey,
			ArgsDigest:             q.ArgsDigest,
			PriceMode:              q.PriceMode,
			Price:                  q.Price,
			FundsMode:              q.FundsMode,
			Phase:                  PhaseAccepted,
			ExecutionOutcome:       OutcomeNotDispatched,
			ChargeStatus:           ChargeNone,
			PaymentStatus:          paymentStatus,
			SettlementStatus:       SettlementNotApplicable,
			ApprovalID:             in.ApprovalID,
			ReconciliationDeadline: now.Add(DefaultReconciliationWindow),
		}
		row := tx.QueryRow(ctx, `INSERT INTO commerce_invocations (`+invocationColumns+`)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,
			        $21,$22,NULL,$23,$24,$25,'',$26,NULL,$27,$28,$28,NULL,1,NULL)
			RETURNING `+invocationColumns,
			v.InvocationID, v.QuoteID, v.QuoteDigest, v.QuoteExpiresAt, v.TermsID, v.TermsVersion,
			v.CapabilityID, v.ProviderID, v.TenantID, v.PrincipalID, v.SubjectPrincipalID, v.DelegationGrantID,
			v.PayerAccountID, v.ExecutionID, v.IdempotencyKey, v.ArgsDigest, v.PriceMode, v.Price.Currency,
			v.Price.AmountMinor, v.FundsMode, v.Phase, v.ExecutionOutcome, v.ChargeStatus, v.PaymentStatus,
			v.SettlementStatus, v.ApprovalID, v.ReconciliationDeadline, now)
		stored, err := scanInvocation(row)
		if uniqueViolationOn(err, "commerce_invocations_tenant_approval") {
			// The approval already belongs to another invocation: it is
			// consumed by one invocation and never authorizes a second
			// (ADR 020 sec. 8).
			return ErrApprovalBound
		}
		if isUniqueViolation(err) {
			// The quote is consumed by another idempotency key: a quote
			// binds one invocation (ADR 020 sec. 5).
			return fmt.Errorf("%w: quote already consumed", ErrQuoteMismatch)
		}
		if err != nil {
			return fmt.Errorf("commerce: insert invocation: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO commerce_invocation_transitions
			(invocation_id, from_phase, to_phase, reason_code, actor, note, recorded_at)
			VALUES ($1, '', $2, '', $3, '', $4)`, stored.InvocationID, PhaseAccepted, id.PrincipalID, now); err != nil {
			return fmt.Errorf("commerce: insert transition: %w", err)
		}
		res = AcceptResult{Invocation: stored}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &res, nil
}

// Transition applies one phase change transactionally with its history
// row (ADR 020 sec. 11). The row is locked, its phase compared with the
// expected one, and a mismatch is ErrPhaseConflict (ErrTerminal when the
// row is already terminal). Fields beside the phase are overwritten only
// when the input sets them.
func (s *Store) Transition(ctx context.Context, tenantID string, in TransitionInput) (*Invocation, error) {
	if err := in.validate(); err != nil {
		return nil, err
	}
	if err := checkText("tenant_id", tenantID, MaxIDBytes, true); err != nil {
		return nil, err
	}
	var out *Invocation
	err := s.withTx(ctx, "commerce:inv:"+in.InvocationID, func(tx pgx.Tx) error {
		next, err := s.applyTransition(ctx, tx, tenantID, in)
		if err != nil {
			return err
		}
		out = next
		return nil
	})
	return out, err
}

// lockInvocation loads one tenant's row FOR UPDATE inside a transaction.
func (s *Store) lockInvocation(ctx context.Context, tx pgx.Tx, tenantID, invocationID string) (*Invocation, error) {
	cur, err := scanInvocation(tx.QueryRow(ctx, `SELECT `+invocationColumns+` FROM commerce_invocations
		WHERE invocation_id = $1 AND tenant_id = $2 FOR UPDATE`, invocationID, tenantID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrInvocationNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("commerce: lock invocation: %w", err)
	}
	return cur, nil
}

// applyTransition is the body of Transition inside a caller's transaction,
// so Reserve, Finalize and Release write their phase change and history row
// in the same commit as the hold they move.
func (s *Store) applyTransition(ctx context.Context, tx pgx.Tx, tenantID string, in TransitionInput) (*Invocation, error) {
	if err := in.validate(); err != nil {
		return nil, err
	}
	var out *Invocation
	err := func() error {
		cur, err := s.lockInvocation(ctx, tx, tenantID, in.InvocationID)
		if err != nil {
			return err
		}
		if IsTerminal(cur.Phase) {
			return fmt.Errorf("%w: %s", ErrTerminal, cur.Phase)
		}
		if cur.Phase != in.ExpectedPhase {
			return fmt.Errorf("%w: phase is %s, expected %s", ErrPhaseConflict, cur.Phase, in.ExpectedPhase)
		}
		now := s.now()
		outcome := firstNonEmpty(in.ExecutionOutcome, cur.ExecutionOutcome)
		charge := firstNonEmpty(in.ChargeStatus, cur.ChargeStatus)
		payment := firstNonEmpty(in.PaymentStatus, cur.PaymentStatus)
		settlement := firstNonEmpty(in.SettlementStatus, cur.SettlementStatus)
		usage := cur.UsageQuantity
		if in.UsageQuantity != nil {
			usage = in.UsageQuantity
		}
		reservation := cur.ReservationDeadline
		if in.ReservationDeadline != nil {
			d := in.ReservationDeadline.UTC()
			reservation = &d
		}
		var finalized *time.Time
		if in.ToPhase == PhaseFinalized {
			finalized = &now
		}
		if in.ToPhase == PhaseReleased && charge == ChargeReserved {
			charge = ChargeReleased
		}
		if in.ToPhase == PhaseOutcomeUnknown {
			outcome = OutcomeUnknown
		}
		if err := checkFactCombination(in.ToPhase, charge, payment); err != nil {
			return err
		}
		if in.ToPhase == PhaseDispatching && cur.PaymentStatus == PaymentUnknown {
			// A hold whose authorization is unknown must not be dispatched
			// (ADR 020 sec. 10). The check reads the fact in the ledger, not
			// the merged one: a caller naming payment_status in the body
			// cannot talk the row past it. Only a retry of reserve, which
			// asks the adapter for the status of the same key, resolves it.
			return fmt.Errorf("%w: authorization of %s is unknown; retry reserve to resolve it before dispatch", ErrPaymentUnknown, in.InvocationID)
		}
		row := tx.QueryRow(ctx, `UPDATE commerce_invocations SET
			phase = $3, execution_outcome = $4, usage_quantity = $5, charge_status = $6,
			payment_status = $7, settlement_status = $8, reason_code = $9,
			reservation_deadline = $10, updated_at = $11, finalized_at = $12, version = version + 1
			WHERE invocation_id = $1 AND tenant_id = $2
			RETURNING `+invocationColumns,
			in.InvocationID, tenantID, in.ToPhase, outcome, usage, charge, payment, settlement,
			firstNonEmpty(in.ReasonCode, cur.ReasonCode), reservation, now, finalized)
		next, err := scanInvocation(row)
		if err != nil {
			return fmt.Errorf("commerce: update invocation: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO commerce_invocation_transitions
			(invocation_id, from_phase, to_phase, reason_code, actor, note, recorded_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			in.InvocationID, cur.Phase, in.ToPhase, in.ReasonCode, in.Actor, in.Note, now); err != nil {
			return fmt.Errorf("commerce: insert transition: %w", err)
		}
		out = next
		return nil
	}()
	return out, err
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// GetInvocation returns one receipt visible to the tenant.
func (s *Store) GetInvocation(ctx context.Context, tenantID, invocationID string) (*Invocation, error) {
	v, err := scanInvocation(s.pool.QueryRow(ctx, `SELECT `+invocationColumns+` FROM commerce_invocations
		WHERE invocation_id = $1 AND tenant_id = $2`, invocationID, tenantID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrInvocationNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("commerce: get invocation: %w", err)
	}
	return v, nil
}

// ListInvocations lists one tenant's receipts, newest first.
func (s *Store) ListInvocations(ctx context.Context, f ListFilter) ([]Invocation, error) {
	if err := checkText("tenant_id", f.TenantID, MaxIDBytes, true); err != nil {
		return nil, err
	}
	// An unknown phase is a refused filter, not an empty listing: a typo must
	// never read as "this tenant has no such invocations" over money rows.
	if f.Phase != "" && !slices.Contains(Phases, f.Phase) {
		return nil, invalid("phase %q is not one of %s", f.Phase, strings.Join(Phases, ", "))
	}
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var sb strings.Builder
	sb.WriteString(`SELECT ` + invocationColumns + ` FROM commerce_invocations WHERE tenant_id = $1`)
	args := []any{f.TenantID}
	add := func(clause string, v any) {
		args = append(args, v)
		fmt.Fprintf(&sb, " AND %s $%d", clause, len(args))
	}
	// The idempotency scope is (tenant, principal, key): a key alone names
	// nothing, so the lookup always carries the principal. A principal on
	// its own scopes the listing the same way.
	if f.IdempotencyKey != "" && f.PrincipalID == "" {
		return nil, invalid("idempotency_key filter requires the caller's principal")
	}
	if f.PrincipalID != "" {
		add("principal_id =", f.PrincipalID)
	}
	if f.IdempotencyKey != "" {
		add("idempotency_key =", f.IdempotencyKey)
	}
	if f.CapabilityID != "" {
		add("capability_id =", f.CapabilityID)
	}
	if f.Phase != "" {
		add("phase =", f.Phase)
	}
	if !f.Since.IsZero() {
		add("created_at >=", f.Since.UTC())
	}
	if !f.Until.IsZero() {
		add("created_at <", f.Until.UTC())
	}
	args = append(args, limit)
	fmt.Fprintf(&sb, " ORDER BY created_at DESC, invocation_id DESC LIMIT $%d", len(args))
	rows, err := s.pool.Query(ctx, sb.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("commerce: list invocations: %w", err)
	}
	defer rows.Close()
	out := []Invocation{}
	for rows.Next() {
		v, err := scanInvocation(rows)
		if err != nil {
			return nil, fmt.Errorf("commerce: scan invocation: %w", err)
		}
		out = append(out, *v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("commerce: list invocations: %w", err)
	}
	return out, nil
}

// ListTransitions returns the append-only history of one invocation.
func (s *Store) ListTransitions(ctx context.Context, tenantID, invocationID string) ([]Transition, error) {
	if _, err := s.GetInvocation(ctx, tenantID, invocationID); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `SELECT seq, invocation_id, from_phase, to_phase, reason_code, actor, note, recorded_at
		FROM commerce_invocation_transitions WHERE invocation_id = $1 ORDER BY seq`, invocationID)
	if err != nil {
		return nil, fmt.Errorf("commerce: list transitions: %w", err)
	}
	defer rows.Close()
	out := []Transition{}
	for rows.Next() {
		var t Transition
		if err := rows.Scan(&t.Seq, &t.InvocationID, &t.FromPhase, &t.ToPhase, &t.ReasonCode, &t.Actor, &t.Note, &t.RecordedAt); err != nil {
			return nil, fmt.Errorf("commerce: scan transition: %w", err)
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("commerce: list transitions: %w", err)
	}
	return out, nil
}

// ListOverdue returns non-terminal invocations past their reconciliation
// deadline, for the operator alert of ADR 020 sec. 11. Crossing the
// deadline changes nothing in the row.
func (s *Store) ListOverdue(ctx context.Context, limit int) ([]Invocation, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `SELECT `+invocationColumns+` FROM commerce_invocations
		WHERE phase NOT IN ('refused', 'released', 'finalized') AND reconciliation_deadline < $1
		ORDER BY reconciliation_deadline LIMIT $2`, s.now(), limit)
	if err != nil {
		return nil, fmt.Errorf("commerce: list overdue: %w", err)
	}
	defer rows.Close()
	out := []Invocation{}
	for rows.Next() {
		v, err := scanInvocation(rows)
		if err != nil {
			return nil, fmt.Errorf("commerce: scan invocation: %w", err)
		}
		out = append(out, *v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("commerce: list overdue: %w", err)
	}
	return out, nil
}

const entitlementColumns = `entitlement_id, tenant_id, capability_id, total_units, remaining_units, reserved_units, invoice_ref, payment_status, granted_by, reason, expires_at, created_at, updated_at`

func scanEntitlement(row pgx.Row) (*Entitlement, error) {
	var e Entitlement
	err := row.Scan(&e.EntitlementID, &e.TenantID, &e.CapabilityID, &e.TotalUnits, &e.RemainingUnits, &e.ReservedUnits,
		&e.InvoiceRef, &e.PaymentStatus, &e.GrantedBy, &e.Reason, &e.ExpiresAt, &e.CreatedAt, &e.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// GrantEntitlement issues a finite entitlement package of units for a capability.
func (s *Store) GrantEntitlement(ctx context.Context, in GrantEntitlementInput) (*Entitlement, error) {
	now := s.now()
	if err := in.validate(now); err != nil {
		return nil, err
	}
	id, err := newULID(now)
	if err != nil {
		return nil, fmt.Errorf("commerce: generate entitlement ulid: %w", err)
	}
	entID := EntitlementIDPrefix + id
	row := s.pool.QueryRow(ctx, `INSERT INTO commerce_entitlements (`+entitlementColumns+`)
		VALUES ($1, $2, $3, $4, $4, 0, $5, 'paid', $6, $7, $8, $9, $9)
		RETURNING `+entitlementColumns,
		entID, in.TenantID, in.CapabilityID, in.Units, in.InvoiceRef, in.Actor, in.Reason, in.ExpiresAt, now)
	ent, err := scanEntitlement(row)
	if err != nil {
		if uniqueViolationOn(err, "commerce_entitlements_invoice") {
			return nil, fmt.Errorf("%w: invoice %s already granted", ErrEntitlementConflict, in.InvoiceRef)
		}
		return nil, fmt.Errorf("commerce: grant entitlement: %w", err)
	}
	return ent, nil
}

// ListEntitlements returns all entitlements of one tenant.
func (s *Store) ListEntitlements(ctx context.Context, tenantID string) ([]Entitlement, error) {
	if err := checkText("tenant_id", tenantID, MaxIDBytes, true); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `SELECT `+entitlementColumns+` FROM commerce_entitlements
		WHERE tenant_id = $1 ORDER BY created_at DESC`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("commerce: list entitlements: %w", err)
	}
	defer rows.Close()
	var out []Entitlement
	for rows.Next() {
		e, err := scanEntitlement(rows)
		if err != nil {
			return nil, fmt.Errorf("commerce: scan entitlement: %w", err)
		}
		out = append(out, *e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("commerce: list entitlements: %w", err)
	}
	if out == nil {
		out = []Entitlement{}
	}
	return out, nil
}

// GetEntitlement returns one entitlement by tenant and entitlement ID.
func (s *Store) GetEntitlement(ctx context.Context, tenantID, entitlementID string) (*Entitlement, error) {
	if err := checkText("tenant_id", tenantID, MaxIDBytes, true); err != nil {
		return nil, err
	}
	if err := checkText("entitlement_id", entitlementID, MaxIDBytes, true); err != nil {
		return nil, err
	}
	row := s.pool.QueryRow(ctx, `SELECT `+entitlementColumns+` FROM commerce_entitlements
		WHERE tenant_id = $1 AND entitlement_id = $2`, tenantID, entitlementID)
	e, err := scanEntitlement(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: entitlement %s", ErrEntitlementNotFound, entitlementID)
	}
	if err != nil {
		return nil, fmt.Errorf("commerce: get entitlement: %w", err)
	}
	return e, nil
}
