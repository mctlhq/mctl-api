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
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
)

// Budget enforcement and the simulated PaymentAuthorizer: C3 of Agent
// Commerce (mctlhq/mctl-api#548), ADR 020 secs. 7, 10 and 12.
//
// A budget is a limit, never a balance. There is nothing to top up: the
// tenant's monthly limit and per-request maximum are set by a platform admin
// through an audited change, and what a tenant can still spend is the limit
// minus what the ledger has captured this period and minus what it holds.
// Simulated credits have no monetary value and cannot be redeemed.
//
// Reservation and payment authorization commit in one database transaction
// (ADR 020 sec. 7 step 8): a denial commits no reservation and leaves nothing
// to release. Every payment operation is idempotent on the key derived from
// the invocation id (sec. 6), so a retry after a crash is recognised rather
// than charged twice.

// DefaultReservationWindow is how long a reservation may sit without a
// dispatch intent before the reconciler releases it (ADR 020 sec. 11).
const DefaultReservationWindow = 15 * time.Minute

// ReservationIDPrefix prefixes reservation ids.
const ReservationIDPrefix = "rsv_"

// Reservation statuses.
const (
	ReservationHeld     = "held"
	ReservationCaptured = "captured"
	ReservationReleased = "released"
)

// ReasonReservationExpired is this API's own reason code for a reservation
// released by the reconciler because its deadline passed with no dispatch
// intent. It is not an ADR 020 sec. 13 code; like phase-conflict it names a
// shape only this ledger produces.
const ReasonReservationExpired = "reservation-expired"

// Payment operations, keyed by PaymentOperationKey (ADR 020 sec. 6).
const (
	PaymentOpAuthorize = "authorize"
	PaymentOpCapture   = "capture"
	PaymentOpVoid      = "void"
)

// Payment results (ADR 020 sec. 10). Unknown and NotFound are never Denied.
const (
	PaymentResultAuthorized = "authorized"
	PaymentResultDenied     = "denied"
	PaymentResultCaptured   = "captured"
	PaymentResultVoided     = "voided"
	PaymentResultFailed     = "failed"
	PaymentResultUnknown    = "unknown"
	PaymentResultNotFound   = "not_found"
)

// Adapter features (ADR 020 sec. 10). The first three are required for any
// paid mode; an adapter missing one is refused at configuration time.
const (
	FeatureAuthCapture     = "auth_capture"
	FeatureVoid            = "void"
	FeatureStatusLookup    = "status_lookup"
	FeaturePartialCapture  = "partial_capture"
	FeatureRefund          = "refund"
	FeatureAsyncSettlement = "async_settlement"
	FeatureSimulation      = "simulation"
)

var requiredFeatures = []string{FeatureAuthCapture, FeatureVoid, FeatureStatusLookup}

var (
	ErrBudgetNotFound     = errors.New("commerce: no budget configured")
	ErrBudgetExhausted    = errors.New("commerce: budget exhausted")
	ErrPaymentDenied      = errors.New("commerce: payment denied")
	ErrPaymentUnknown     = errors.New("commerce: payment outcome unknown")
	ErrPaymentConflict    = errors.New("commerce: payment key reused with different parameters")
	ErrReservationMissing = errors.New("commerce: reservation missing for a reserved invocation")
	ErrAdapterIneligible  = errors.New("commerce: payment adapter ineligible")
)

// Budget is one payer account's limits (ADR 020 secs. 2 and 7). FundsMode is
// always simulated in the milestone and is set server-side.
type Budget struct {
	SchemaVersion      int       `json:"schema_version"`
	TenantID           string    `json:"tenant_id"`
	PayerAccountID     string    `json:"payer_account_id"`
	Currency           string    `json:"currency"`
	FundsMode          string    `json:"funds_mode"`
	MonthlyLimitMinor  int64     `json:"monthly_limit_minor"`
	PerRequestMaxMinor int64     `json:"per_request_max_minor"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
	Version            int64     `json:"version"`
}

// SetBudgetInput creates or changes a budget. Every change names its actor
// and reason: a limit is granted, never self-granted.
type SetBudgetInput struct {
	TenantID           string
	PayerAccountID     string
	Currency           string
	MonthlyLimitMinor  int64
	PerRequestMaxMinor int64
	Actor              string
	Reason             string
}

func (in SetBudgetInput) validate() error {
	for _, f := range []struct {
		name, value string
		max         int
	}{
		{"tenant_id", in.TenantID, MaxIDBytes},
		{"payer_account_id", in.PayerAccountID, MaxIDBytes},
		{"actor", in.Actor, MaxIDBytes},
		{"reason", in.Reason, MaxReasonBytes},
	} {
		if err := checkText(f.name, f.value, f.max, true); err != nil {
			return err
		}
	}
	if _, ok := currencyExponents[in.Currency]; !ok {
		return invalid("currency %q is not a supported ISO 4217 code", in.Currency)
	}
	if in.MonthlyLimitMinor < 0 {
		return invalid("monthly_limit_minor must be >= 0")
	}
	if in.PerRequestMaxMinor < 1 {
		return invalid("per_request_max_minor must be >= 1")
	}
	return nil
}

// BudgetChange is one append-only row of the budget's history.
type BudgetChange struct {
	Seq                   int64     `json:"seq"`
	TenantID              string    `json:"tenant_id"`
	PayerAccountID        string    `json:"payer_account_id"`
	Actor                 string    `json:"actor"`
	Reason                string    `json:"reason"`
	OldCurrency           string    `json:"old_currency,omitempty"`
	OldMonthlyLimitMinor  *int64    `json:"old_monthly_limit_minor,omitempty"`
	OldPerRequestMaxMinor *int64    `json:"old_per_request_max_minor,omitempty"`
	NewCurrency           string    `json:"new_currency"`
	NewMonthlyLimitMinor  int64     `json:"new_monthly_limit_minor"`
	NewPerRequestMaxMinor int64     `json:"new_per_request_max_minor"`
	RecordedAt            time.Time `json:"recorded_at"`
}

// Balance is the tenant read of ADR 020 sec. 12. Committed is what this
// period captured. Reserved is every held reservation whose invocation is
// still moving, and PendingLiability every held reservation whose outcome is
// unknown, both regardless of the period they were reserved in: a hold from
// last month does not become spendable because the month changed. Available
// is the limit minus all three, never below zero.
type Balance struct {
	SchemaVersion         int       `json:"schema_version"`
	TenantID              string    `json:"tenant_id"`
	PayerAccountID        string    `json:"payer_account_id"`
	Currency              string    `json:"currency"`
	FundsMode             string    `json:"funds_mode"`
	Period                string    `json:"period"`
	MonthlyLimitMinor     int64     `json:"monthly_limit_minor"`
	PerRequestMaxMinor    int64     `json:"per_request_max_minor"`
	CommittedMinor        int64     `json:"committed_minor"`
	ReservedMinor         int64     `json:"reserved_minor"`
	PendingLiabilityMinor int64     `json:"pending_liability_minor"`
	AvailableMinor        int64     `json:"available_minor"`
	AsOf                  time.Time `json:"as_of"`
}

// Reservation is one hold against a budget, bound to exactly one invocation.
// Period is the UTC month it was reserved in; a capture is attributed to it.
type Reservation struct {
	SchemaVersion   int       `json:"schema_version"`
	ReservationID   string    `json:"reservation_id"`
	InvocationID    string    `json:"invocation_id"`
	TenantID        string    `json:"tenant_id"`
	PayerAccountID  string    `json:"payer_account_id"`
	Period          string    `json:"period"`
	Currency        string    `json:"currency"`
	AmountMinor     int64     `json:"amount_minor"`
	Status          string    `json:"status"`
	AuthorizationID string    `json:"authorization_id,omitempty"`
	CaptureID       string    `json:"capture_id,omitempty"`
	Deadline        time.Time `json:"deadline"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// PrecheckResult is the non-binding answer of ADR 020 sec. 7 step 4. It
// holds nothing; step 8 decides again.
type PrecheckResult struct {
	Sufficient bool    `json:"sufficient"`
	ReasonCode string  `json:"reason_code,omitempty"`
	Balance    Balance `json:"balance"`
}

// ---- PaymentAuthorizer ---------------------------------------------------

// AdapterInfo is what an adapter declares for feature negotiation.
type AdapterInfo struct {
	AdapterID      string   `json:"adapter_id"`
	AdapterVersion string   `json:"adapter_version"`
	FundsModes     []string `json:"funds_modes"`
	Features       []string `json:"features"`
}

// PaymentRequest is the input of authorize (ADR 020 sec. 10). A payment
// proof, when a future rail needs one, is an input here and nowhere else.
type PaymentRequest struct {
	Key            string
	InvocationID   string
	TenantID       string
	PayerAccountID string
	Money          Money
	FundsMode      string
	QuoteDigest    string
}

// PaymentResult is the recorded outcome of one operation. ID is the
// authorization or capture id; Reason explains a denial or failure.
type PaymentResult struct {
	Operation  string    `json:"operation"`
	Result     string    `json:"result"`
	ID         string    `json:"id,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	Settlement string    `json:"settlement_status,omitempty"`
	RecordedAt time.Time `json:"recorded_at"`
}

// PaymentAuthorizer is the one interface the core talks to every rail
// through (ADR 020 sec. 10). Every operation is idempotent on its key: the
// same key with the same parameters returns the recorded result, the same key
// with different parameters is ErrPaymentConflict. The querier is the
// ledger transaction, so a simulated adapter commits with the reservation;
// a future external rail ignores it and the core treats its answer as
// unknown until status confirms it.
type PaymentAuthorizer interface {
	Adapter() AdapterInfo
	Authorize(ctx context.Context, q querier, req PaymentRequest) (PaymentResult, error)
	Capture(ctx context.Context, q querier, key, authorizationID string, amount Money) (PaymentResult, error)
	Void(ctx context.Context, q querier, key, authorizationID string) (PaymentResult, error)
	Status(ctx context.Context, q querier, key string) (PaymentResult, error)
}

// checkAdapter refuses an adapter that lacks a required feature or does not
// support simulated funds. It runs at configuration time, never at the
// first payment.
func checkAdapter(info AdapterInfo) error {
	if info.AdapterID == "" || info.AdapterVersion == "" {
		return fmt.Errorf("%w: adapter_id and adapter_version are required", ErrAdapterIneligible)
	}
	for _, f := range requiredFeatures {
		if !slices.Contains(info.Features, f) {
			return fmt.Errorf("%w: %s lacks required feature %s", ErrAdapterIneligible, info.AdapterID, f)
		}
	}
	if !slices.Contains(info.FundsModes, FundsModeSimulated) {
		return fmt.Errorf("%w: %s does not support simulated funds", ErrAdapterIneligible, info.AdapterID)
	}
	return nil
}

// UseAuthorizer installs a payment adapter after feature negotiation.
func (s *Store) UseAuthorizer(a PaymentAuthorizer) error {
	if a == nil {
		return fmt.Errorf("%w: nil adapter", ErrAdapterIneligible)
	}
	if err := checkAdapter(a.Adapter()); err != nil {
		return err
	}
	s.auth = a
	return nil
}

// SimulatedAuthorizer is the milestone adapter: it records every operation
// in commerce_payment_operations inside the ledger transaction, authorizes
// any simulated request the budget already admitted, and refuses live funds.
// Captures are settled on record and move no value.
type SimulatedAuthorizer struct {
	now func() time.Time
}

// Adapter declares the simulated adapter's features.
func (SimulatedAuthorizer) Adapter() AdapterInfo {
	return AdapterInfo{
		AdapterID: "simulated", AdapterVersion: "1",
		FundsModes: []string{FundsModeSimulated},
		Features:   []string{FeatureAuthCapture, FeatureVoid, FeatureStatusLookup, FeatureSimulation},
	}
}

func (a SimulatedAuthorizer) clock() time.Time {
	if a.now != nil {
		return a.now()
	}
	return time.Now().UTC()
}

const paymentOpColumns = `op_key, invocation_id, operation, tenant_id, payer_account_id, currency, amount_minor,
	funds_mode, quote_digest, authorization_id, result, result_id, reason, settlement_status, recorded_at`

type paymentOp struct {
	Key, InvocationID, Operation, TenantID, PayerAccountID, Currency string
	AmountMinor                                                      int64
	FundsMode, QuoteDigest, AuthorizationID                          string
	Result, ResultID, Reason, Settlement                             string
	RecordedAt                                                       time.Time
}

func (op paymentOp) result() PaymentResult {
	return PaymentResult{Operation: op.Operation, Result: op.Result, ID: op.ResultID, Reason: op.Reason,
		Settlement: op.Settlement, RecordedAt: op.RecordedAt}
}

func loadPaymentOp(ctx context.Context, q querier, key string) (*paymentOp, error) {
	var op paymentOp
	err := q.QueryRow(ctx, `SELECT `+paymentOpColumns+` FROM commerce_payment_operations WHERE op_key = $1`, key).Scan(
		&op.Key, &op.InvocationID, &op.Operation, &op.TenantID, &op.PayerAccountID, &op.Currency, &op.AmountMinor,
		&op.FundsMode, &op.QuoteDigest, &op.AuthorizationID, &op.Result, &op.ResultID, &op.Reason, &op.Settlement, &op.RecordedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("commerce: load payment operation: %w", err)
	}
	return &op, nil
}

func insertPaymentOp(ctx context.Context, q querier, op paymentOp) error {
	_, err := q.Exec(ctx, `INSERT INTO commerce_payment_operations (`+paymentOpColumns+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
		op.Key, op.InvocationID, op.Operation, op.TenantID, op.PayerAccountID, op.Currency, op.AmountMinor,
		op.FundsMode, op.QuoteDigest, op.AuthorizationID, op.Result, op.ResultID, op.Reason, op.Settlement, op.RecordedAt)
	if err != nil {
		return fmt.Errorf("commerce: record payment operation: %w", err)
	}
	return nil
}

// Authorize records authorized for a simulated request, denied for any other
// funds mode. The same key with different parameters is a conflict.
func (a SimulatedAuthorizer) Authorize(ctx context.Context, q querier, req PaymentRequest) (PaymentResult, error) {
	prior, err := loadPaymentOp(ctx, q, req.Key)
	if err != nil {
		return PaymentResult{}, err
	}
	if prior != nil {
		if prior.Operation != PaymentOpAuthorize || prior.InvocationID != req.InvocationID || prior.TenantID != req.TenantID ||
			prior.PayerAccountID != req.PayerAccountID || prior.Currency != req.Money.Currency ||
			prior.AmountMinor != req.Money.AmountMinor || prior.FundsMode != req.FundsMode || prior.QuoteDigest != req.QuoteDigest {
			return PaymentResult{}, fmt.Errorf("%w: %s", ErrPaymentConflict, req.Key)
		}
		return prior.result(), nil
	}
	op := paymentOp{Key: req.Key, InvocationID: req.InvocationID, Operation: PaymentOpAuthorize, TenantID: req.TenantID,
		PayerAccountID: req.PayerAccountID, Currency: req.Money.Currency, AmountMinor: req.Money.AmountMinor,
		FundsMode: req.FundsMode, QuoteDigest: req.QuoteDigest, Settlement: SettlementNotApplicable, RecordedAt: a.clock()}
	if req.FundsMode != FundsModeSimulated {
		op.Result, op.Reason = PaymentResultDenied, ReasonFundsModeUnavailable
	} else {
		id, err := newULID(op.RecordedAt)
		if err != nil {
			return PaymentResult{}, err
		}
		op.Result, op.ResultID = PaymentResultAuthorized, "sauth_"+id
	}
	if err := insertPaymentOp(ctx, q, op); err != nil {
		return PaymentResult{}, err
	}
	return op.result(), nil
}

// settle is the shared body of Capture and Void: find the authorization the
// key refers to, refuse an amount above it, and record the result.
func (a SimulatedAuthorizer) settle(ctx context.Context, q querier, operation, key, authorizationID string, amount *Money) (PaymentResult, error) {
	prior, err := loadPaymentOp(ctx, q, key)
	if err != nil {
		return PaymentResult{}, err
	}
	if prior != nil {
		same := prior.Operation == operation && prior.AuthorizationID == authorizationID
		if amount != nil {
			same = same && prior.Currency == amount.Currency && prior.AmountMinor == amount.AmountMinor
		}
		if !same {
			return PaymentResult{}, fmt.Errorf("%w: %s", ErrPaymentConflict, key)
		}
		return prior.result(), nil
	}
	var auth paymentOp
	err = q.QueryRow(ctx, `SELECT `+paymentOpColumns+` FROM commerce_payment_operations
		WHERE operation = $1 AND result_id = $2 AND result = $3`, PaymentOpAuthorize, authorizationID, PaymentResultAuthorized).Scan(
		&auth.Key, &auth.InvocationID, &auth.Operation, &auth.TenantID, &auth.PayerAccountID, &auth.Currency, &auth.AmountMinor,
		&auth.FundsMode, &auth.QuoteDigest, &auth.AuthorizationID, &auth.Result, &auth.ResultID, &auth.Reason, &auth.Settlement, &auth.RecordedAt)
	op := paymentOp{Key: key, Operation: operation, AuthorizationID: authorizationID, Settlement: SettlementNotApplicable, RecordedAt: a.clock()}
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		op.Result, op.Reason = PaymentResultFailed, "authorization not found"
	case err != nil:
		return PaymentResult{}, fmt.Errorf("commerce: load authorization: %w", err)
	default:
		op.InvocationID, op.TenantID, op.PayerAccountID = auth.InvocationID, auth.TenantID, auth.PayerAccountID
		op.Currency, op.AmountMinor, op.FundsMode, op.QuoteDigest = auth.Currency, auth.AmountMinor, auth.FundsMode, auth.QuoteDigest
		if amount != nil {
			op.Currency, op.AmountMinor = amount.Currency, amount.AmountMinor
		}
		id, err := newULID(op.RecordedAt)
		if err != nil {
			return PaymentResult{}, err
		}
		switch {
		case amount != nil && (amount.Currency != auth.Currency || amount.AmountMinor > auth.AmountMinor):
			op.Result, op.Reason = PaymentResultFailed, "capture exceeds authorization"
		case operation == PaymentOpCapture:
			op.Result, op.ResultID, op.Settlement = PaymentResultCaptured, "scap_"+id, SettlementSettled
		default:
			op.Result, op.ResultID = PaymentResultVoided, "svoid_"+id
		}
	}
	if err := insertPaymentOp(ctx, q, op); err != nil {
		return PaymentResult{}, err
	}
	return op.result(), nil
}

// Capture records a simulated capture, settled on record.
func (a SimulatedAuthorizer) Capture(ctx context.Context, q querier, key, authorizationID string, amount Money) (PaymentResult, error) {
	return a.settle(ctx, q, PaymentOpCapture, key, authorizationID, &amount)
}

// Void records a simulated void.
func (a SimulatedAuthorizer) Void(ctx context.Context, q querier, key, authorizationID string) (PaymentResult, error) {
	return a.settle(ctx, q, PaymentOpVoid, key, authorizationID, nil)
}

// Status returns the recorded result for a key, or not_found.
func (SimulatedAuthorizer) Status(ctx context.Context, q querier, key string) (PaymentResult, error) {
	op, err := loadPaymentOp(ctx, q, key)
	if err != nil {
		return PaymentResult{}, err
	}
	if op == nil {
		return PaymentResult{Result: PaymentResultNotFound}, nil
	}
	return op.result(), nil
}

// ---- budgets ------------------------------------------------------------

const budgetColumns = `tenant_id, payer_account_id, currency, funds_mode, monthly_limit_minor, per_request_max_minor,
	created_at, updated_at, version`

func scanBudget(row pgx.Row) (*Budget, error) {
	var b Budget
	if err := row.Scan(&b.TenantID, &b.PayerAccountID, &b.Currency, &b.FundsMode, &b.MonthlyLimitMinor, &b.PerRequestMaxMinor,
		&b.CreatedAt, &b.UpdatedAt, &b.Version); err != nil {
		return nil, err
	}
	b.SchemaVersion = SchemaVersion
	return &b, nil
}

func budgetLockKey(tenantID string) string { return "commerce:budget:" + tenantID }

// SetBudget creates or changes a payer account's limits and appends the
// change to the account's history. The currency is fixed once the account
// has ever reserved, settled or not: a capture of this period in the old
// currency beside a limit in the new one would make committed meaningless,
// and history is never rewritten. A tenant that needs another currency
// gets another payer account.
func (s *Store) SetBudget(ctx context.Context, in SetBudgetInput) (*Budget, error) {
	if err := in.validate(); err != nil {
		return nil, err
	}
	var out *Budget
	err := s.withTx(ctx, budgetLockKey(in.TenantID), func(tx pgx.Tx) error {
		now := s.now()
		prior, err := scanBudget(tx.QueryRow(ctx, `SELECT `+budgetColumns+` FROM commerce_budgets
			WHERE tenant_id = $1 AND payer_account_id = $2 FOR UPDATE`, in.TenantID, in.PayerAccountID))
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			prior = nil
		case err != nil:
			return fmt.Errorf("commerce: load budget: %w", err)
		}
		if prior != nil && prior.Currency != in.Currency {
			var n int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM commerce_reservations WHERE tenant_id = $1 AND payer_account_id = $2`,
				in.TenantID, in.PayerAccountID).Scan(&n); err != nil {
				return fmt.Errorf("commerce: count reservations: %w", err)
			}
			if n > 0 {
				return fmt.Errorf("%w: currency is fixed once the account has ever reserved", ErrCurrencyMismatch)
			}
		}
		row := tx.QueryRow(ctx, `INSERT INTO commerce_budgets (`+budgetColumns+`)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $7, 1)
			ON CONFLICT (tenant_id, payer_account_id) DO UPDATE SET
				currency = EXCLUDED.currency, monthly_limit_minor = EXCLUDED.monthly_limit_minor,
				per_request_max_minor = EXCLUDED.per_request_max_minor, updated_at = EXCLUDED.updated_at,
				version = commerce_budgets.version + 1
			RETURNING `+budgetColumns,
			in.TenantID, in.PayerAccountID, in.Currency, FundsModeSimulated, in.MonthlyLimitMinor, in.PerRequestMaxMinor, now)
		b, err := scanBudget(row)
		if err != nil {
			return fmt.Errorf("commerce: upsert budget: %w", err)
		}
		var oldCurrency *string
		var oldLimit, oldMax *int64
		if prior != nil {
			oldCurrency, oldLimit, oldMax = &prior.Currency, &prior.MonthlyLimitMinor, &prior.PerRequestMaxMinor
		}
		if _, err := tx.Exec(ctx, `INSERT INTO commerce_budget_changes
			(tenant_id, payer_account_id, actor, reason, old_currency, old_monthly_limit_minor, old_per_request_max_minor,
			 new_currency, new_monthly_limit_minor, new_per_request_max_minor, recorded_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
			in.TenantID, in.PayerAccountID, in.Actor, in.Reason, oldCurrency, oldLimit, oldMax,
			b.Currency, b.MonthlyLimitMinor, b.PerRequestMaxMinor, now); err != nil {
			return fmt.Errorf("commerce: record budget change: %w", err)
		}
		out = b
		return nil
	})
	return out, err
}

// GetBudget returns the limits of one payer account.
func (s *Store) GetBudget(ctx context.Context, tenantID, payerAccountID string) (*Budget, error) {
	return s.getBudget(ctx, s.pool, tenantID, payerAccountID, false)
}

func (s *Store) getBudget(ctx context.Context, q querier, tenantID, payerAccountID string, lock bool) (*Budget, error) {
	suffix := ""
	if lock {
		suffix = " FOR UPDATE"
	}
	b, err := scanBudget(q.QueryRow(ctx, `SELECT `+budgetColumns+` FROM commerce_budgets
		WHERE tenant_id = $1 AND payer_account_id = $2`+suffix, tenantID, payerAccountID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrBudgetNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("commerce: load budget: %w", err)
	}
	return b, nil
}

// ListBudgetChanges returns the account's history, oldest first.
func (s *Store) ListBudgetChanges(ctx context.Context, tenantID, payerAccountID string) ([]BudgetChange, error) {
	rows, err := s.pool.Query(ctx, `SELECT seq, tenant_id, payer_account_id, actor, reason, old_currency,
		old_monthly_limit_minor, old_per_request_max_minor, new_currency, new_monthly_limit_minor, new_per_request_max_minor, recorded_at
		FROM commerce_budget_changes WHERE tenant_id = $1 AND payer_account_id = $2 ORDER BY seq`, tenantID, payerAccountID)
	if err != nil {
		return nil, fmt.Errorf("commerce: list budget changes: %w", err)
	}
	defer rows.Close()
	out := []BudgetChange{}
	for rows.Next() {
		var c BudgetChange
		var oldCurrency *string
		if err := rows.Scan(&c.Seq, &c.TenantID, &c.PayerAccountID, &c.Actor, &c.Reason, &oldCurrency,
			&c.OldMonthlyLimitMinor, &c.OldPerRequestMaxMinor, &c.NewCurrency, &c.NewMonthlyLimitMinor, &c.NewPerRequestMaxMinor, &c.RecordedAt); err != nil {
			return nil, fmt.Errorf("commerce: scan budget change: %w", err)
		}
		if oldCurrency != nil {
			c.OldCurrency = *oldCurrency
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("commerce: list budget changes: %w", err)
	}
	return out, nil
}

// Period is the UTC month a moment belongs to, the budget period of ADR 020
// sec. 7 ("tenant monthly budgets in UTC").
func Period(t time.Time) string { return t.UTC().Format("2006-01") }

// balanceOf computes the three sums for an account at now. Held
// reservations count whatever period they were reserved in.
func (s *Store) balanceOf(ctx context.Context, q querier, b *Budget, now time.Time) (*Balance, error) {
	bal := Balance{SchemaVersion: SchemaVersion, TenantID: b.TenantID, PayerAccountID: b.PayerAccountID, Currency: b.Currency,
		FundsMode: b.FundsMode, Period: Period(now), MonthlyLimitMinor: b.MonthlyLimitMinor, PerRequestMaxMinor: b.PerRequestMaxMinor, AsOf: now}
	if err := q.QueryRow(ctx, `SELECT
			COALESCE(SUM(CASE WHEN r.status = $3 AND r.period = $4 THEN r.amount_minor END), 0),
			COALESCE(SUM(CASE WHEN r.status = $5 AND i.phase <> $6 THEN r.amount_minor END), 0),
			COALESCE(SUM(CASE WHEN r.status = $5 AND i.phase = $6 THEN r.amount_minor END), 0)
		FROM commerce_reservations r JOIN commerce_invocations i USING (invocation_id)
		WHERE r.tenant_id = $1 AND r.payer_account_id = $2`,
		b.TenantID, b.PayerAccountID, ReservationCaptured, bal.Period, ReservationHeld, PhaseOutcomeUnknown).Scan(
		&bal.CommittedMinor, &bal.ReservedMinor, &bal.PendingLiabilityMinor); err != nil {
		return nil, fmt.Errorf("commerce: sum reservations: %w", err)
	}
	bal.AvailableMinor = max(b.MonthlyLimitMinor-bal.CommittedMinor-bal.ReservedMinor-bal.PendingLiabilityMinor, 0)
	return &bal, nil
}

// GetBalance is the tenant budget read of ADR 020 sec. 12.
func (s *Store) GetBalance(ctx context.Context, tenantID, payerAccountID string) (*Balance, error) {
	// One snapshot for the limits and the sums, so a concurrent SetBudget or
	// Reserve cannot be observed half-applied: available_minor is always
	// consistent with the numbers printed beside it.
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, fmt.Errorf("commerce: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	b, err := s.getBudget(ctx, tx, tenantID, payerAccountID, false)
	if err != nil {
		return nil, err
	}
	bal, err := s.balanceOf(ctx, tx, b, s.now())
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commerce: commit: %w", err)
	}
	return bal, nil
}

// admits is the budget decision shared by Precheck and Reserve: a currency
// outside the account's is a mismatch; an amount above the per-request
// maximum or above what is available is exhausted. It is a pure function of
// the balance so the two cannot disagree.
func admits(bal *Balance, amount Money) (string, error) {
	if amount.Currency != bal.Currency {
		return "", fmt.Errorf("%w: account is %s, request is %s", ErrCurrencyMismatch, bal.Currency, amount.Currency)
	}
	if amount.AmountMinor > bal.PerRequestMaxMinor {
		return "exceeds per-request maximum", nil
	}
	if amount.AmountMinor > bal.AvailableMinor {
		return "exceeds available budget", nil
	}
	return "", nil
}

// Precheck is the preliminary, non-binding budget check of ADR 020 sec. 7
// step 4. It holds nothing, so an approval can wait as long as it needs; the
// binding decision is Reserve, after the approval.
func (s *Store) Precheck(ctx context.Context, tenantID, payerAccountID string, amount Money) (*PrecheckResult, error) {
	if err := amount.validate("amount"); err != nil {
		return nil, err
	}
	bal, err := s.GetBalance(ctx, tenantID, payerAccountID)
	if err != nil {
		return nil, err
	}
	note, err := admits(bal, amount)
	if err != nil {
		return nil, err
	}
	res := &PrecheckResult{Sufficient: note == "", Balance: *bal}
	if note != "" {
		res.ReasonCode = ReasonBudgetExhausted
	}
	return res, nil
}

// ---- reservations ---------------------------------------------------------

const reservationColumns = `reservation_id, invocation_id, tenant_id, payer_account_id, period, currency, amount_minor,
	status, authorization_id, capture_id, deadline, created_at, updated_at`

func scanReservation(row pgx.Row) (*Reservation, error) {
	var r Reservation
	if err := row.Scan(&r.ReservationID, &r.InvocationID, &r.TenantID, &r.PayerAccountID, &r.Period, &r.Currency, &r.AmountMinor,
		&r.Status, &r.AuthorizationID, &r.CaptureID, &r.Deadline, &r.CreatedAt, &r.UpdatedAt); err != nil {
		return nil, err
	}
	r.SchemaVersion = SchemaVersion
	return &r, nil
}

func (s *Store) reservationOf(ctx context.Context, q querier, invocationID string, lock bool) (*Reservation, error) {
	suffix := ""
	if lock {
		suffix = " FOR UPDATE"
	}
	r, err := scanReservation(q.QueryRow(ctx, `SELECT `+reservationColumns+` FROM commerce_reservations
		WHERE invocation_id = $1`+suffix, invocationID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("commerce: load reservation: %w", err)
	}
	return r, nil
}

// GetReservation returns the reservation bound to an invocation of the
// tenant, or nil when none was made.
func (s *Store) GetReservation(ctx context.Context, tenantID, invocationID string) (*Reservation, error) {
	if _, err := s.GetInvocation(ctx, tenantID, invocationID); err != nil {
		return nil, err
	}
	return s.reservationOf(ctx, s.pool, invocationID, false)
}

func (s *Store) setReservationStatus(ctx context.Context, q querier, reservationID, status, captureID string, now time.Time) (*Reservation, error) {
	r, err := scanReservation(q.QueryRow(ctx, `UPDATE commerce_reservations SET status = $2, capture_id = $3, updated_at = $4
		WHERE reservation_id = $1 RETURNING `+reservationColumns, reservationID, status, captureID, now))
	if err != nil {
		return nil, fmt.Errorf("commerce: update reservation: %w", err)
	}
	return r, nil
}

// ReserveInput is step 8 of ADR 020 sec. 7 for one accepted invocation.
type ReserveInput struct {
	TenantID     string
	InvocationID string
	Actor        string
}

// ReserveResult is the reserved invocation and its hold. Replayed reports
// that the hold already existed. When the adapter answered unknown, the
// invocation is reserved with payment_status unknown; applyTransition
// refuses to dispatch it until a retry of Reserve resolves it by status.
type ReserveResult struct {
	Invocation  *Invocation  `json:"invocation"`
	Reservation *Reservation `json:"reservation,omitempty"`
	Replayed    bool         `json:"replayed"`
}

// reserveRefusals are the reasons Reserve itself refuses with, each with the
// error a retry answers. It is the one place this vocabulary lives: the
// handler's error envelope and refusedError both read it.
var reserveRefusals = map[string]error{
	ReasonBudgetExhausted:      ErrBudgetExhausted,
	ReasonPaymentDenied:        ErrPaymentDenied,
	ReasonQuoteExpired:         ErrQuoteExpired,
	ReasonCurrencyMismatch:     ErrCurrencyMismatch,
	ReasonFundsModeUnavailable: ErrFundsModeUnavailable,
	ReasonEntitlementExhausted: ErrEntitlementExhausted,
	ReasonEntitlementExpired:   ErrEntitlementExpired,
}

// IsReserveRefusal reports whether reason is one Reserve refuses with, as
// opposed to a reason some other caller stamped on a refused row.
func IsReserveRefusal(reason string) bool { return reserveRefusals[reason] != nil }

// refusedError maps a refused row back to the error its refusal was, so a
// retry of Reserve answers the same thing the first call did.
func refusedError(reason string) error {
	if err := reserveRefusals[reason]; err != nil {
		return err
	}
	return fmt.Errorf("%w: %s", ErrTerminal, PhaseRefused)
}

// Reserve atomically compares committed plus held against the monthly
// limit, holds the quoted amount and authorizes payment, all in one
// transaction under the account lock. A denial of any kind commits the
// invocation as refused with its reason and holds nothing. A second call for
// the same invocation returns the existing hold, never a second one.
func (s *Store) Reserve(ctx context.Context, in ReserveInput) (*ReserveResult, error) {
	if err := checkText("tenant_id", in.TenantID, MaxIDBytes, true); err != nil {
		return nil, err
	}
	if err := checkText("invocation_id", in.InvocationID, MaxIDBytes, true); err != nil {
		return nil, err
	}
	if err := checkText("actor", in.Actor, MaxIDBytes, true); err != nil {
		return nil, err
	}
	var res ReserveResult
	var refusal error
	err := s.withTx(ctx, budgetLockKey(in.TenantID), func(tx pgx.Tx) error {
		cur, err := s.lockInvocation(ctx, tx, in.TenantID, in.InvocationID)
		if err != nil {
			return err
		}
		if cur.Phase != PhaseAccepted {
			if cur.Phase == PhaseRefused {
				// The row is handed back with the error so the caller can
				// see the refusal is final, like the first answer was.
				res = ReserveResult{Invocation: cur}
				refusal = refusedError(cur.ReasonCode)
				return nil
			}
			rsv, err := s.reservationOf(ctx, tx, cur.InvocationID, true)
			if err != nil {
				return err
			}
			// Only a live hold replays. A captured or released row still has
			// its reservation, and answering it as a reservation would tell
			// a retrying gateway it holds budget for a settled invocation.
			if rsv == nil || rsv.Status != ReservationHeld {
				return fmt.Errorf("%w: phase is %s, expected %s", ErrPhaseConflict, cur.Phase, PhaseAccepted)
			}
			if cur.Phase == PhaseReserved && cur.PaymentStatus == PaymentUnknown {
				return s.resolveUnknownHold(ctx, tx, in, cur, rsv, &res, &refusal)
			}
			res = ReserveResult{Invocation: cur, Reservation: rsv, Replayed: true}
			return nil
		}
		now := s.now()
		refuse := func(reason, note string, cause error) error {
			inv, err := s.applyTransition(ctx, tx, in.TenantID, TransitionInput{
				InvocationID: cur.InvocationID, ExpectedPhase: PhaseAccepted, ToPhase: PhaseRefused,
				ReasonCode: reason, Actor: in.Actor, Note: note,
			})
			if err != nil {
				return err
			}
			res = ReserveResult{Invocation: inv}
			refusal = cause
			return nil
		}
		if !now.Before(cur.QuoteExpiresAt) {
			return refuse(ReasonQuoteExpired, "quote expired before reservation", ErrQuoteExpired)
		}
		if err := checkFundsMode(cur.FundsMode); err != nil {
			return refuse(ReasonFundsModeUnavailable, err.Error(), err)
		}
		b, err := s.getBudget(ctx, tx, in.TenantID, cur.PayerAccountID, true)
		if errors.Is(err, ErrBudgetNotFound) {
			return refuse(ReasonBudgetExhausted, "no budget configured for "+cur.PayerAccountID, ErrBudgetExhausted)
		}
		if err != nil {
			return err
		}
		bal, err := s.balanceOf(ctx, tx, b, now)
		if err != nil {
			return err
		}
		note, err := admits(bal, cur.Price)
		if errors.Is(err, ErrCurrencyMismatch) {
			return refuse(ReasonCurrencyMismatch, err.Error(), err)
		}
		if err != nil {
			return err
		}
		if note != "" {
			return refuse(ReasonBudgetExhausted, note, ErrBudgetExhausted)
		}
		if err := s.holdEntitlementUnit(ctx, tx, cur.TenantID, cur.CapabilityID, cur.InvocationID, now); err != nil {
			if errors.Is(err, ErrEntitlementExhausted) {
				return refuse(ReasonEntitlementExhausted, "prepaid entitlement units exhausted", ErrEntitlementExhausted)
			}
			if errors.Is(err, ErrEntitlementExpired) {
				return refuse(ReasonEntitlementExpired, "prepaid entitlement package expired", ErrEntitlementExpired)
			}
			return err
		}
		payment := PaymentNotRequired
		authorizationID := ""
		if cur.PriceMode != PriceModeFree {
			pr, err := s.auth.Authorize(ctx, tx, PaymentRequest{
				Key: PaymentOperationKey(cur.InvocationID, PaymentOpAuthorize), InvocationID: cur.InvocationID,
				TenantID: cur.TenantID, PayerAccountID: cur.PayerAccountID, Money: cur.Price, FundsMode: cur.FundsMode,
				QuoteDigest: cur.QuoteDigest,
			})
			if err != nil {
				return err
			}
			switch pr.Result {
			case PaymentResultAuthorized:
				payment, authorizationID = PaymentAuthorized, pr.ID
			case PaymentResultDenied:
				if err := s.releaseEntitlementUnit(ctx, tx, cur.InvocationID, now); err != nil {
					return err
				}
				// Nothing was inserted yet: the denial commits no reservation
				// (ADR 020 sec. 11).
				return refuse(ReasonPaymentDenied, pr.Reason, ErrPaymentDenied)
			case PaymentResultUnknown:
				// Unknown is never denied: the hold stays and only status on
				// the same key resolves it.
				payment = PaymentUnknown
			default:
				return fmt.Errorf("commerce: authorize returned %q", pr.Result)
			}
		}
		id, err := newULID(now)
		if err != nil {
			return err
		}
		deadline := now.Add(DefaultReservationWindow)
		rsv, err := scanReservation(tx.QueryRow(ctx, `INSERT INTO commerce_reservations (`+reservationColumns+`)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'',$10,$11,$11) RETURNING `+reservationColumns,
			ReservationIDPrefix+id, cur.InvocationID, cur.TenantID, cur.PayerAccountID, Period(now), cur.Price.Currency,
			cur.Price.AmountMinor, ReservationHeld, authorizationID, deadline, now))
		if err != nil {
			return fmt.Errorf("commerce: insert reservation: %w", err)
		}
		inv, err := s.applyTransition(ctx, tx, in.TenantID, TransitionInput{
			InvocationID: cur.InvocationID, ExpectedPhase: PhaseAccepted, ToPhase: PhaseReserved, Actor: in.Actor,
			ChargeStatus: ChargeReserved, PaymentStatus: payment, ReservationDeadline: &deadline,
		})
		if err != nil {
			return err
		}
		res = ReserveResult{Invocation: inv, Reservation: rsv}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if refusal != nil {
		return &res, refusal
	}
	return &res, nil
}

// resolveUnknownHold is the retry path of a hold whose authorize answered
// unknown: the adapter is asked for the status of the same key (ADR 020
// sec. 10), never for a fresh authorization. Authorized is recorded on the
// row and the hold replays; denied releases the hold with nothing to void
// and reports the denial; still unknown leaves everything as it was. Until
// this resolves, applyTransition refuses to dispatch the row.
func (s *Store) resolveUnknownHold(ctx context.Context, tx pgx.Tx, in ReserveInput, cur *Invocation, rsv *Reservation, res *ReserveResult, refusal *error) error {
	_, denied, err := s.resolveAuthorization(ctx, tx, cur, rsv) // the id is written onto rsv
	if err != nil {
		return err
	}
	now := s.now()
	if denied {
		updated, err := s.setReservationStatus(ctx, tx, rsv.ReservationID, ReservationReleased, "", now)
		if err != nil {
			return err
		}
		inv, err := s.applyTransition(ctx, tx, in.TenantID, TransitionInput{
			InvocationID: cur.InvocationID, ExpectedPhase: PhaseReserved, ToPhase: PhaseReleased,
			ReasonCode: ReasonPaymentDenied, Actor: in.Actor, Note: "authorization resolved denied before dispatch",
			ExecutionOutcome: OutcomeNotDispatched, ChargeStatus: ChargeReleased, PaymentStatus: PaymentDenied,
		})
		if err != nil {
			return err
		}
		if err := s.releaseEntitlementUnit(ctx, tx, cur.InvocationID, now); err != nil {
			return err
		}
		*res = ReserveResult{Invocation: inv, Reservation: updated}
		*refusal = fmt.Errorf("%w: authorization was denied", ErrPaymentDenied)
		return nil
	}
	row := tx.QueryRow(ctx, `UPDATE commerce_invocations SET payment_status = $3, updated_at = $4, version = version + 1
		WHERE invocation_id = $1 AND tenant_id = $2 RETURNING `+invocationColumns,
		cur.InvocationID, in.TenantID, PaymentAuthorized, now)
	inv, err := scanInvocation(row)
	if err != nil {
		return fmt.Errorf("commerce: record authorization: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO commerce_invocation_transitions
		(invocation_id, from_phase, to_phase, reason_code, actor, note, recorded_at)
		VALUES ($1, $2, $2, '', $3, $4, $5)`,
		cur.InvocationID, PhaseReserved, in.Actor, "authorization resolved by status lookup", now); err != nil {
		return fmt.Errorf("commerce: insert transition: %w", err)
	}
	*res = ReserveResult{Invocation: inv, Reservation: rsv, Replayed: true}
	return nil
}

// FinalizeInput records a confirmed outcome and settles the charge (ADR 020
// sec. 7 steps 10-11).
type FinalizeInput struct {
	TenantID         string
	InvocationID     string
	Actor            string
	ExecutionOutcome string
	UsageQuantity    *int64
	Note             string
}

// FinalizeResult is the finalized invocation and its reservation.
type FinalizeResult struct {
	Invocation  *Invocation  `json:"invocation"`
	Reservation *Reservation `json:"reservation,omitempty"`
	Replayed    bool         `json:"replayed"`
}

// Finalize captures or releases exactly once: per_call captures on any
// confirmed outcome, per_successful_call captures on success and releases
// on failure, free terms capture nothing. It accepts a dispatched or
// outcome_unknown row; the second is the reconciler resolving a definitive
// outcome. A finalized row answers the same result again for the same
// outcome, and a phase conflict for a different one.
func (s *Store) Finalize(ctx context.Context, in FinalizeInput) (*FinalizeResult, error) {
	for _, f := range []struct{ name, value string }{{"tenant_id", in.TenantID}, {"invocation_id", in.InvocationID}, {"actor", in.Actor}} {
		if err := checkText(f.name, f.value, MaxIDBytes, true); err != nil {
			return nil, err
		}
	}
	if err := checkText("note", in.Note, MaxReasonBytes, false); err != nil {
		return nil, err
	}
	if in.ExecutionOutcome != OutcomeSucceeded && in.ExecutionOutcome != OutcomeFailed {
		return nil, invalid("execution_outcome must be succeeded or failed")
	}
	if in.UsageQuantity != nil && *in.UsageQuantity < 0 {
		return nil, invalid("usage_quantity must be >= 0")
	}
	var res FinalizeResult
	err := s.withTx(ctx, budgetLockKey(in.TenantID), func(tx pgx.Tx) error {
		cur, err := s.lockInvocation(ctx, tx, in.TenantID, in.InvocationID)
		if err != nil {
			return err
		}
		rsv, err := s.reservationOf(ctx, tx, cur.InvocationID, true)
		if err != nil {
			return err
		}
		if cur.Phase == PhaseFinalized {
			if cur.ExecutionOutcome != in.ExecutionOutcome {
				return fmt.Errorf("%w: already finalized as %s", ErrPhaseConflict, cur.ExecutionOutcome)
			}
			res = FinalizeResult{Invocation: cur, Reservation: rsv, Replayed: true}
			return nil
		}
		if IsTerminal(cur.Phase) {
			return fmt.Errorf("%w: %s", ErrTerminal, cur.Phase)
		}
		if cur.Phase != PhaseDispatched && cur.Phase != PhaseOutcomeUnknown {
			return fmt.Errorf("%w: phase is %s, expected %s or %s", ErrPhaseConflict, cur.Phase, PhaseDispatched, PhaseOutcomeUnknown)
		}
		if rsv == nil || rsv.Status != ReservationHeld {
			return fmt.Errorf("%w: %s", ErrReservationMissing, cur.InvocationID)
		}
		now := s.now()
		capture := cur.PriceMode == PriceModeFree || cur.PriceMode == PriceModePerCall ||
			(cur.PriceMode == PriceModePerSuccessfulCall && in.ExecutionOutcome == OutcomeSucceeded)
		usage := in.UsageQuantity
		if usage == nil {
			one := int64(1)
			usage = &one
		}
		tr := TransitionInput{InvocationID: cur.InvocationID, ExpectedPhase: cur.Phase, ToPhase: PhaseFinalized,
			Actor: in.Actor, Note: in.Note, ExecutionOutcome: in.ExecutionOutcome, UsageQuantity: usage}
		captureID := ""
		status := ReservationReleased
		denied := false
		if cur.PriceMode != PriceModeFree {
			if _, denied, err = s.resolveAuthorization(ctx, tx, cur, rsv); err != nil {
				return err
			}
		}
		switch {
		case cur.PriceMode == PriceModeFree:
			// Nothing to capture: a free hold of zero is recorded captured
			// so the receipt reads "charged 0", not "released".
			tr.ChargeStatus, status = ChargeCaptured, ReservationCaptured
		case denied:
			// The rail denied what the ledger had held as unknown. There is
			// nothing to capture or void: the hold is released and the
			// receipt says the payment was denied, so the row can finalize
			// instead of erroring on every retry with its hold stuck.
			tr.ChargeStatus, tr.PaymentStatus, tr.SettlementStatus = ChargeReleased, PaymentDenied, SettlementNotApplicable
		case capture:
			pr, err := s.settlePayment(ctx, tx, PaymentOpCapture, cur, rsv)
			if err != nil {
				return err
			}
			captureID = pr.ID
			tr.ChargeStatus, tr.PaymentStatus, tr.SettlementStatus, status = ChargeCaptured, PaymentCaptured, pr.Settlement, ReservationCaptured
			if tr.SettlementStatus == "" {
				tr.SettlementStatus = SettlementPending
			}
		default:
			if _, err := s.settlePayment(ctx, tx, PaymentOpVoid, cur, rsv); err != nil {
				return err
			}
			tr.ChargeStatus, tr.PaymentStatus, tr.SettlementStatus = ChargeReleased, PaymentVoided, SettlementNotApplicable
		}
		updated, err := s.setReservationStatus(ctx, tx, rsv.ReservationID, status, captureID, now)
		if err != nil {
			return err
		}
		if status == ReservationCaptured {
			if err := s.captureEntitlementUnit(ctx, tx, cur.InvocationID, now); err != nil {
				return err
			}
		} else {
			if err := s.releaseEntitlementUnit(ctx, tx, cur.InvocationID, now); err != nil {
				return err
			}
		}
		inv, err := s.applyTransition(ctx, tx, in.TenantID, tr)
		if err != nil {
			return err
		}
		res = FinalizeResult{Invocation: inv, Reservation: updated}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &res, nil
}

// resolveAuthorization returns the authorization a capture or void refers
// to. A hold whose authorize answered unknown has none recorded yet, so the
// adapter is asked for the status of the authorize key: authorized fills it
// in, denied reports it, and anything else is still unknown (ADR 020 sec.
// 10: resolved only by status on the same key, never by a fresh operation).
func (s *Store) resolveAuthorization(ctx context.Context, tx pgx.Tx, cur *Invocation, rsv *Reservation) (authID string, denied bool, err error) {
	if rsv.AuthorizationID != "" {
		return rsv.AuthorizationID, false, nil
	}
	key := PaymentOperationKey(cur.InvocationID, PaymentOpAuthorize)
	st, err := s.auth.Status(ctx, tx, key)
	if err != nil {
		return "", false, err
	}
	switch st.Result {
	case PaymentResultAuthorized:
		if _, err := tx.Exec(ctx, `UPDATE commerce_reservations SET authorization_id = $2 WHERE reservation_id = $1`, rsv.ReservationID, st.ID); err != nil {
			return "", false, fmt.Errorf("commerce: record authorization: %w", err)
		}
		rsv.AuthorizationID = st.ID // the next caller in this transaction reads the field
		return st.ID, false, nil
	case PaymentResultDenied:
		return "", true, nil
	default:
		return "", false, fmt.Errorf("%w: %s", ErrPaymentUnknown, key)
	}
}

// settlePayment runs capture or void on the invocation's derived key. It
// asks status first, so a retry after a lost response resolves the recorded
// operation instead of issuing a fresh one (ADR 020 sec. 10). Unknown is
// returned as ErrPaymentUnknown and the transaction rolls back: the hold
// stays exactly as it was.
func (s *Store) settlePayment(ctx context.Context, tx pgx.Tx, operation string, cur *Invocation, rsv *Reservation) (PaymentResult, error) {
	authID, denied, err := s.resolveAuthorization(ctx, tx, cur, rsv)
	if err != nil {
		return PaymentResult{}, err
	}
	if denied {
		return PaymentResult{}, fmt.Errorf("%w: authorization was denied", ErrPaymentDenied)
	}
	key := PaymentOperationKey(cur.InvocationID, operation)
	pr, err := s.auth.Status(ctx, tx, key)
	if err != nil {
		return PaymentResult{}, err
	}
	if pr.Result == PaymentResultNotFound || pr.Result == PaymentResultUnknown {
		if operation == PaymentOpCapture {
			pr, err = s.auth.Capture(ctx, tx, key, authID, cur.Price)
		} else {
			pr, err = s.auth.Void(ctx, tx, key, authID)
		}
		if err != nil {
			return PaymentResult{}, err
		}
	}
	want := PaymentResultCaptured
	if operation == PaymentOpVoid {
		want = PaymentResultVoided
	}
	switch pr.Result {
	case want:
		return pr, nil
	case PaymentResultUnknown:
		return PaymentResult{}, fmt.Errorf("%w: %s", ErrPaymentUnknown, key)
	case PaymentResultFailed:
		return PaymentResult{}, fmt.Errorf("%w: %s %s", ErrPaymentDenied, operation, pr.Reason)
	default:
		return PaymentResult{}, fmt.Errorf("commerce: %s returned %q", operation, pr.Result)
	}
}

// ReleaseInput releases a hold before dispatch (ADR 020 sec. 11: failure
// before the provider accepts, or cancellation before dispatch).
type ReleaseInput struct {
	TenantID     string
	InvocationID string
	Actor        string
	ReasonCode   string
	Note         string
}

// Release voids the authorization and releases the hold of a reserved or
// dispatching invocation. A dispatched row cannot be released: its outcome
// must be observed (too-late-to-cancel). A released row answers itself
// again.
func (s *Store) Release(ctx context.Context, in ReleaseInput) (*FinalizeResult, error) {
	for _, f := range []struct{ name, value string }{{"tenant_id", in.TenantID}, {"invocation_id", in.InvocationID}, {"actor", in.Actor}, {"reason_code", in.ReasonCode}} {
		if err := checkText(f.name, f.value, MaxIDBytes, true); err != nil {
			return nil, err
		}
	}
	if err := checkText("note", in.Note, MaxReasonBytes, false); err != nil {
		return nil, err
	}
	var res FinalizeResult
	err := s.withTx(ctx, budgetLockKey(in.TenantID), func(tx pgx.Tx) error {
		cur, err := s.lockInvocation(ctx, tx, in.TenantID, in.InvocationID)
		if err != nil {
			return err
		}
		rsv, err := s.reservationOf(ctx, tx, cur.InvocationID, true)
		if err != nil {
			return err
		}
		if cur.Phase == PhaseReleased {
			res = FinalizeResult{Invocation: cur, Reservation: rsv, Replayed: true}
			return nil
		}
		if IsTerminal(cur.Phase) {
			return fmt.Errorf("%w: %s", ErrTerminal, cur.Phase)
		}
		if cur.Phase != PhaseReserved && cur.Phase != PhaseDispatching {
			return fmt.Errorf("%w: phase is %s, only %s or %s can be released", ErrPhaseConflict, cur.Phase, PhaseReserved, PhaseDispatching)
		}
		if rsv == nil || rsv.Status != ReservationHeld {
			return fmt.Errorf("%w: %s", ErrReservationMissing, cur.InvocationID)
		}
		tr := TransitionInput{InvocationID: cur.InvocationID, ExpectedPhase: cur.Phase, ToPhase: PhaseReleased,
			Actor: in.Actor, ReasonCode: in.ReasonCode, Note: in.Note, ExecutionOutcome: OutcomeNotDispatched, ChargeStatus: ChargeReleased}
		if cur.PriceMode != PriceModeFree {
			_, denied, err := s.resolveAuthorization(ctx, tx, cur, rsv)
			if err != nil {
				return err
			}
			if denied {
				// The rail denied what the ledger had held as unknown: there
				// is nothing to void (ADR 020 sec. 11, external rail row).
				tr.PaymentStatus = PaymentDenied
			} else {
				if _, err := s.settlePayment(ctx, tx, PaymentOpVoid, cur, rsv); err != nil {
					return err
				}
				tr.PaymentStatus = PaymentVoided
			}
		}
		updated, err := s.setReservationStatus(ctx, tx, rsv.ReservationID, ReservationReleased, "", s.now())
		if err != nil {
			return err
		}
		if err := s.releaseEntitlementUnit(ctx, tx, cur.InvocationID, s.now()); err != nil {
			return err
		}
		inv, err := s.applyTransition(ctx, tx, in.TenantID, tr)
		if err != nil {
			return err
		}
		res = FinalizeResult{Invocation: inv, Reservation: updated}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &res, nil
}

// ExpireResult lists what one reconciler pass changed. Unresolved names the
// reserved rows past their deadline whose payment the adapter could not
// confirm or void: they stay held for an operator, never dropped.
type ExpireResult struct {
	Refused    []string `json:"refused"`
	Released   []string `json:"released"`
	Unresolved []string `json:"unresolved"`
}

// ExpireStale is the reconciler of ADR 020 sec. 11 for the two states time
// alone may resolve: an accepted row whose quote expired is refused, and a
// reserved row with no dispatch intent whose deadline passed is released. A
// dispatching, dispatched or outcome_unknown row is never touched here,
// however old: its liability is resolved only by the provider's outcome.
func (s *Store) ExpireStale(ctx context.Context, actor string, limit int) (*ExpireResult, error) {
	if err := checkText("actor", actor, MaxIDBytes, true); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	now := s.now()
	out := &ExpireResult{Refused: []string{}, Released: []string{}, Unresolved: []string{}}
	type ref struct{ tenant, id string }
	list := func(query, phase string) ([]ref, error) {
		rows, err := s.pool.Query(ctx, query, now, limit, phase)
		if err != nil {
			return nil, fmt.Errorf("commerce: list stale: %w", err)
		}
		defer rows.Close()
		var refs []ref
		for rows.Next() {
			var r ref
			if err := rows.Scan(&r.tenant, &r.id); err != nil {
				return nil, fmt.Errorf("commerce: scan stale: %w", err)
			}
			refs = append(refs, r)
		}
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("commerce: list stale: %w", err)
		}
		return refs, nil
	}
	accepted, err := list(`SELECT tenant_id, invocation_id FROM commerce_invocations
		WHERE phase = $3 AND quote_expires_at < $1 ORDER BY quote_expires_at LIMIT $2`, PhaseAccepted)
	if err != nil {
		return nil, err
	}
	for _, r := range accepted {
		_, err := s.Transition(ctx, r.tenant, TransitionInput{InvocationID: r.id, ExpectedPhase: PhaseAccepted, ToPhase: PhaseRefused,
			ReasonCode: ReasonQuoteExpired, Actor: actor, Note: "reconciler: quote expired with nothing reserved"})
		if errors.Is(err, ErrPhaseConflict) || errors.Is(err, ErrTerminal) {
			continue // moved by someone else between the listing and the lock
		}
		if err != nil {
			return out, err
		}
		out.Refused = append(out.Refused, r.id)
	}
	reserved, err := list(`SELECT tenant_id, invocation_id FROM commerce_invocations
		WHERE phase = $3 AND reservation_deadline < $1 ORDER BY reservation_deadline LIMIT $2`, PhaseReserved)
	if err != nil {
		return out, err
	}
	for _, r := range reserved {
		_, err := s.Release(ctx, ReleaseInput{TenantID: r.tenant, InvocationID: r.id, Actor: actor,
			ReasonCode: ReasonReservationExpired, Note: "reconciler: reservation deadline passed with no dispatch intent"})
		switch {
		case errors.Is(err, ErrPhaseConflict), errors.Is(err, ErrTerminal):
			continue
		case errors.Is(err, ErrPaymentUnknown), errors.Is(err, ErrPaymentDenied):
			out.Unresolved = append(out.Unresolved, r.id)
			continue
		case err != nil:
			return out, err
		}
		out.Released = append(out.Released, r.id)
	}
	return out, nil
}

// holdEntitlementUnit locks and decrements a unit from the earliest-expiring active
// entitlement for (tenantID, capabilityID).
//
// The entitlement ledger (prepaid capability units) and the budget ledger (currency
// limits and rail authorization) operate independently in this phase. A held entitlement
// unit tracks service entitlement consumption, while the invocation's price mode governs
// rail authorization and spend limits. When an entitlement is held alongside a priced
// capability, both ledgers record the execution.
//
// If the tenant has an entitlement registered for this capability but all units are
// consumed or expired, holdEntitlementUnit returns ErrEntitlementExhausted or
// ErrEntitlementExpired to refuse the reservation. If the tenant has no entitlements
// configured for this capability, it returns nil so execution proceeds under standard budget.
func (s *Store) holdEntitlementUnit(ctx context.Context, tx pgx.Tx, tenantID, capabilityID, invocationID string, now time.Time) error {
	var entID string
	err := tx.QueryRow(ctx, `SELECT entitlement_id
		FROM commerce_entitlements
		WHERE tenant_id = $1 AND capability_id = $2 AND status = 'active' AND remaining_units > 0 AND expires_at > $3
		ORDER BY expires_at ASC LIMIT 1 FOR UPDATE`,
		tenantID, capabilityID, now).Scan(&entID)
	if err == nil {
		_, err = tx.Exec(ctx, `UPDATE commerce_entitlements
			SET remaining_units = remaining_units - 1, reserved_units = reserved_units + 1, updated_at = $2
			WHERE entitlement_id = $1`, entID, now)
		if err != nil {
			return fmt.Errorf("commerce: reserve entitlement unit: %w", err)
		}
		alcULID, err := newULID(now)
		if err != nil {
			return fmt.Errorf("commerce: generate allocation ulid: %w", err)
		}
		_, err = tx.Exec(ctx, `INSERT INTO commerce_entitlement_allocations
			(allocation_id, entitlement_id, invocation_id, units, state, recorded_at)
			VALUES ($1, $2, $3, 1, $4, $5)`,
			AllocationIDPrefix+alcULID, entID, invocationID, AllocationStateHeld, now)
		if err != nil {
			return fmt.Errorf("commerce: record entitlement allocation: %w", err)
		}
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("commerce: check entitlement: %w", err)
	}

	// No active units found. Check whether this tenant has active entitlements for this capability.
	// 1. Never configured or all retired: activePackages == 0 -> return nil (fall back to currency budget)
	// 2. Active package exists (expires_at > now) but all units consumed -> ErrEntitlementExhausted
	// 3. Active package exists but all active packages have expired (expires_at <= now) -> ErrEntitlementExpired
	var activePackages, unexpiredPackages int64
	err = tx.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE expires_at > $3)
		FROM commerce_entitlements
		WHERE tenant_id = $1 AND capability_id = $2 AND status = 'active'`, tenantID, capabilityID, now).Scan(&activePackages, &unexpiredPackages)
	if err != nil {
		return fmt.Errorf("commerce: check entitlement count: %w", err)
	}
	if activePackages == 0 {
		// Not an entitlement-backed capability for this tenant (or all packages retired).
		return nil
	}
	if unexpiredPackages > 0 {
		return ErrEntitlementExhausted
	}
	return ErrEntitlementExpired
}

func (s *Store) captureEntitlementUnit(ctx context.Context, tx pgx.Tx, invocationID string, now time.Time) error {
	var alcID, entID string
	var units int64
	err := tx.QueryRow(ctx, `SELECT allocation_id, entitlement_id, units
		FROM commerce_entitlement_allocations WHERE invocation_id = $1 AND state = $2
		FOR UPDATE`, invocationID, AllocationStateHeld).Scan(&alcID, &entID, &units)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("commerce: find held allocation: %w", err)
	}
	_, err = tx.Exec(ctx, `UPDATE commerce_entitlement_allocations SET state = $2 WHERE allocation_id = $1`,
		alcID, AllocationStateCaptured)
	if err != nil {
		return fmt.Errorf("commerce: capture allocation: %w", err)
	}
	_, err = tx.Exec(ctx, `UPDATE commerce_entitlements
		SET reserved_units = reserved_units - $2, updated_at = $3
		WHERE entitlement_id = $1`, entID, units, now)
	if err != nil {
		return fmt.Errorf("commerce: commit entitlement unit: %w", err)
	}
	return nil
}

func (s *Store) releaseEntitlementUnit(ctx context.Context, tx pgx.Tx, invocationID string, now time.Time) error {
	var alcID, entID string
	var units int64
	err := tx.QueryRow(ctx, `SELECT allocation_id, entitlement_id, units
		FROM commerce_entitlement_allocations WHERE invocation_id = $1 AND state = $2
		FOR UPDATE`, invocationID, AllocationStateHeld).Scan(&alcID, &entID, &units)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("commerce: find held allocation: %w", err)
	}
	_, err = tx.Exec(ctx, `UPDATE commerce_entitlement_allocations SET state = $2 WHERE allocation_id = $1`,
		alcID, AllocationStateReleased)
	if err != nil {
		return fmt.Errorf("commerce: release allocation: %w", err)
	}
	_, err = tx.Exec(ctx, `UPDATE commerce_entitlements
		SET remaining_units = remaining_units + $2, reserved_units = reserved_units - $2, updated_at = $3
		WHERE entitlement_id = $1`, entID, units, now)
	if err != nil {
		return fmt.Errorf("commerce: restore entitlement unit: %w", err)
	}
	return nil
}
