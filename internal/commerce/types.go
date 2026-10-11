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

// Package commerce is the durable commerce ledger of ADR 020
// (mctl-agents docs/adr/020-capability-commerce-contract.md): commerce terms,
// quotes, invocations and their transition history. It implements C2 of
// Agent Commerce (mctlhq/mctl-api#547).
//
// It is a sibling of internal/usage, not an extension of it. Usage holds
// platform expense (model cost); this package holds customer spend. The two
// are never summed (ADR 020 sec. 1).
//
// Budget reservations, capture and release belong to C3 (mctl-api#548). This
// package records the invocation phases they move through and refuses a
// transition that does not match the current phase.
package commerce

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// SchemaVersion is the envelope version every record carries (ADR 020
// sec. 14). A consumer refuses a version it does not understand.
const SchemaVersion = 1

// Identifier prefixes (ADR 020 secs. 4-6).
const (
	TermsIDPrefix      = "ctm_"
	QuoteIDPrefix      = "cq_"
	InvocationIDPrefix = "inv_"
)

// Price modes (ADR 020 sec. 4).
const (
	PriceModeFree              = "free"
	PriceModePerCall           = "per_call"
	PriceModePerSuccessfulCall = "per_successful_call"
)

// Funds modes (ADR 020 sec. 2). Live is refused everywhere in the milestone.
const (
	FundsModeSimulated = "simulated"
	FundsModeLive      = "live"
)

// MeterInvocation is the only meter in the milestone.
const MeterInvocation = "invocation"

// Quote TTL bounds in seconds (ADR 020 sec. 4).
const (
	MinQuoteTTLSeconds = 30
	MaxQuoteTTLSeconds = 900
)

// Invocation phases (ADR 020 sec. 11).
const (
	PhaseAccepted       = "accepted"
	PhaseRefused        = "refused"
	PhaseReserved       = "reserved"
	PhaseDispatching    = "dispatching"
	PhaseDispatched     = "dispatched"
	PhaseOutcomeUnknown = "outcome_unknown"
	PhaseReleased       = "released"
	PhaseFinalized      = "finalized"
)

// Execution outcomes, charge, payment and settlement statuses (ADR 020
// secs. 10-11). They are the five facts of sec. 1 and are stored apart.
const (
	OutcomeNotDispatched = "not_dispatched"
	OutcomeSucceeded     = "succeeded"
	OutcomeFailed        = "failed"
	OutcomeUnknown       = "unknown"

	ChargeNone     = "none"
	ChargeReserved = "reserved"
	ChargeCaptured = "captured"
	ChargeReleased = "released"

	// PaymentNone is the state of a paid invocation before C3 authorizes
	// it; it mirrors ChargeNone and is a C2 addition to ADR 020 sec. 11.
	PaymentNone        = "none"
	PaymentNotRequired = "not_required"
	PaymentAuthorized  = "authorized"
	PaymentDenied      = "denied"
	PaymentCaptured    = "captured"
	PaymentVoided      = "voided"
	PaymentUnknown     = "unknown"

	SettlementNotApplicable = "not_applicable"
	SettlementPending       = "pending"
	SettlementSettled       = "settled"
	SettlementFailed        = "failed"
)

// Reason codes (ADR 020 sec. 13), additive to ADR 017 sec. 7.
const (
	ReasonIdentityUnresolved   = "identity-unresolved"
	ReasonTermsUnknown         = "commerce-terms-unknown"
	ReasonQuoteExpired         = "quote-expired"
	ReasonQuoteStale           = "quote-stale"
	ReasonQuoteMismatch        = "quote-mismatch"
	ReasonIdempotencyConflict  = "idempotency-conflict"
	ReasonCurrencyMismatch     = "currency-mismatch"
	ReasonFundsModeUnavailable = "funds-mode-unavailable"
	ReasonBudgetExhausted      = "budget-exhausted"
	ReasonPaymentDenied        = "payment-denied"
	ReasonUnsupportedExecution = "unsupported-execution"
	ReasonOutcomeUnknown       = "outcome-unknown"
	ReasonTooLateToCancel      = "too-late-to-cancel"
)

// Encoding version prefixes of the two digests (ADR 020 secs. 5 and 8).
const (
	quoteEncodingVersion = "mctl-commerce-quote/v1"
	termsEncodingVersion = "mctl-commerce-terms/v1"
)

// Field bounds. Identifiers and digests are short; the limits exist so a
// client cannot store a payload in an id column.
const (
	MaxIDBytes           = 256
	MaxCapabilityIDBytes = 1024
	MaxIdempotencyKey    = 128
	MaxReasonBytes       = 1024
)

var (
	ErrInvalid              = errors.New("commerce: invalid")
	ErrTermsNotFound        = errors.New("commerce: terms not found")
	ErrTermsVersionMissing  = errors.New("commerce: no such terms version")
	ErrQuoteNotFound        = errors.New("commerce: quote not found")
	ErrInvocationNotFound   = errors.New("commerce: invocation not found")
	ErrIdempotencyConflict  = errors.New("commerce: idempotency conflict")
	ErrQuoteExpired         = errors.New("commerce: quote expired")
	ErrQuoteStale           = errors.New("commerce: quote stale")
	ErrQuoteMismatch        = errors.New("commerce: quote mismatch")
	ErrCurrencyMismatch     = errors.New("commerce: currency mismatch")
	ErrFundsModeUnavailable = errors.New("commerce: funds mode unavailable")
	ErrTermsRetired         = errors.New("commerce: terms retired")
	ErrPhaseConflict        = errors.New("commerce: phase conflict")
	ErrTerminal             = errors.New("commerce: invocation is terminal")
)

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// Money is an integer amount in a currency's minor unit (ADR 020 sec. 2).
// There is deliberately no float anywhere in this package.
type Money struct {
	Currency    string `json:"currency"`
	AmountMinor int64  `json:"amount_minor"`
}

// currencyExponents is the checked-in ISO 4217 minor-unit table. A currency
// absent here is refused, never defaulted to two decimals.
var currencyExponents = map[string]int{
	"EUR": 2, "USD": 2, "GBP": 2, "CHF": 2, "PLN": 2, "CZK": 2, "SEK": 2,
	"NOK": 2, "DKK": 2, "CAD": 2, "AUD": 2, "JPY": 0, "KRW": 0, "UZS": 2,
	"RUB": 2, "TRY": 2, "AED": 2, "SGD": 2, "HKD": 2, "INR": 2, "BRL": 2,
	"KWD": 3, "BHD": 3, "JOD": 3, "TND": 3,
}

// CurrencyExponent returns the minor-unit exponent of an ISO 4217 code.
func CurrencyExponent(code string) (int, bool) {
	e, ok := currencyExponents[code]
	return e, ok
}

func (m Money) validate(where string) error {
	if _, ok := currencyExponents[m.Currency]; !ok {
		return invalid("%s.currency %q is not a supported ISO 4217 code", where, m.Currency)
	}
	if m.AmountMinor < 0 {
		return invalid("%s.amount_minor must be >= 0", where)
	}
	return nil
}

// Terms is one immutable, versioned price declaration (ADR 020 sec. 4).
type Terms struct {
	SchemaVersion   int        `json:"schema_version"`
	TermsID         string     `json:"terms_id"`
	TermsVersion    int64      `json:"terms_version"`
	CapabilityID    string     `json:"capability_id"`
	InputSchemaHash string     `json:"input_schema_hash"`
	ProviderID      string     `json:"provider_id"`
	PriceMode       string     `json:"price_mode"`
	Meter           string     `json:"meter"`
	Price           Money      `json:"price"`
	FundsMode       string     `json:"funds_mode"`
	QuoteTTLSeconds int        `json:"quote_ttl_seconds"`
	EffectiveFrom   time.Time  `json:"effective_from"`
	RetiredAt       *time.Time `json:"retired_at,omitempty"`
	PublishedBy     string     `json:"published_by"`
	CreatedAt       time.Time  `json:"created_at"`
}

// PublishTermsInput publishes a new terms version. A new TermsID is minted
// when the input names none; naming an existing one publishes the next
// version of it.
type PublishTermsInput struct {
	TermsID         string
	CapabilityID    string
	InputSchemaHash string
	ProviderID      string
	PriceMode       string
	Price           Money
	FundsMode       string
	QuoteTTLSeconds int
	EffectiveFrom   time.Time
	PublishedBy     string
}

var sha256Pattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func checkText(name, value string, max int, required bool) error {
	if value == "" {
		if required {
			return invalid("%s is required", name)
		}
		return nil
	}
	if len(value) > max {
		return invalid("%s exceeds %d bytes", name, max)
	}
	if strings.ContainsAny(value, "\n\r\x00") {
		return invalid("%s contains a control character", name)
	}
	return nil
}

func checkDigest(name, value string) error {
	if !sha256Pattern.MatchString(value) {
		return invalid("%s must be sha256:<64 hex>", name)
	}
	return nil
}

func (in PublishTermsInput) validate() error {
	for _, f := range []struct {
		name, value string
		max         int
		required    bool
	}{
		{"terms_id", in.TermsID, MaxIDBytes, false},
		{"capability_id", in.CapabilityID, MaxCapabilityIDBytes, true},
		{"provider_id", in.ProviderID, MaxIDBytes, true},
		{"published_by", in.PublishedBy, MaxIDBytes, true},
	} {
		if err := checkText(f.name, f.value, f.max, f.required); err != nil {
			return err
		}
	}
	if in.TermsID != "" && !strings.HasPrefix(in.TermsID, TermsIDPrefix) {
		return invalid("terms_id must start with %s", TermsIDPrefix)
	}
	if !strings.HasPrefix(in.CapabilityID, "mctl://") {
		return invalid("capability_id must be an mctl:// capability URI")
	}
	if err := checkDigest("input_schema_hash", in.InputSchemaHash); err != nil {
		return err
	}
	switch in.PriceMode {
	case PriceModeFree, PriceModePerCall, PriceModePerSuccessfulCall:
	default:
		return invalid("price_mode %q is not free, per_call or per_successful_call", in.PriceMode)
	}
	if err := in.Price.validate("price"); err != nil {
		return err
	}
	if in.PriceMode == PriceModeFree && in.Price.AmountMinor != 0 {
		return invalid("free terms must price 0")
	}
	if in.PriceMode != PriceModeFree && in.Price.AmountMinor == 0 {
		return invalid("%s terms must price more than 0", in.PriceMode)
	}
	if err := checkFundsMode(in.FundsMode); err != nil {
		return err
	}
	if in.QuoteTTLSeconds < MinQuoteTTLSeconds || in.QuoteTTLSeconds > MaxQuoteTTLSeconds {
		return invalid("quote_ttl_seconds must be within %d..%d", MinQuoteTTLSeconds, MaxQuoteTTLSeconds)
	}
	if in.EffectiveFrom.IsZero() {
		return invalid("effective_from is required")
	}
	return nil
}

// checkFundsMode admits simulated only. ADR 020 sec. 2: a component that
// receives live before a separately reviewed scope enables it refuses.
func checkFundsMode(mode string) error {
	switch mode {
	case FundsModeSimulated:
		return nil
	case FundsModeLive:
		return fmt.Errorf("%w: %s", ErrFundsModeUnavailable, "live funds are not enabled")
	default:
		return invalid("funds_mode %q is not simulated or live", mode)
	}
}

// Identities are the server-resolved parties of a quote or invocation (ADR
// 020 sec. 3). None of them is ever read from a request body.
type Identities struct {
	TenantID           string `json:"tenant_id"`
	PrincipalID        string `json:"principal_id"`
	SubjectPrincipalID string `json:"subject_principal_id"`
	DelegationGrantID  string `json:"delegation_grant_id,omitempty"`
	PayerAccountID     string `json:"payer_account_id"`
	ExecutionID        string `json:"execution_id"`
}

func (id Identities) validate() error {
	for _, f := range []struct {
		name, value string
		required    bool
	}{
		{"tenant_id", id.TenantID, true},
		{"principal_id", id.PrincipalID, true},
		{"subject_principal_id", id.SubjectPrincipalID, true},
		{"delegation_grant_id", id.DelegationGrantID, false},
		{"payer_account_id", id.PayerAccountID, true},
		{"execution_id", id.ExecutionID, true},
	} {
		if err := checkText(f.name, f.value, MaxIDBytes, f.required); err != nil {
			return err
		}
	}
	if id.SubjectPrincipalID != id.PrincipalID && id.DelegationGrantID == "" {
		return invalid("delegation_grant_id is required when subject_principal_id differs from principal_id")
	}
	if id.SubjectPrincipalID == id.PrincipalID && id.DelegationGrantID != "" {
		return invalid("delegation_grant_id must be empty when the subject is the principal")
	}
	return nil
}

// Quote is a server-minted, immutable offer (ADR 020 sec. 5).
type Quote struct {
	SchemaVersion   int    `json:"schema_version"`
	QuoteID         string `json:"quote_id"`
	TermsID         string `json:"terms_id"`
	TermsVersion    int64  `json:"terms_version"`
	CapabilityID    string `json:"capability_id"`
	InputSchemaHash string `json:"input_schema_hash"`
	Identities
	ArgsDigest  string    `json:"args_digest"`
	PriceMode   string    `json:"price_mode"`
	Price       Money     `json:"price"`
	FundsMode   string    `json:"funds_mode"`
	ExpiresAt   time.Time `json:"expires_at"`
	QuoteDigest string    `json:"quote_digest"`
	CreatedAt   time.Time `json:"created_at"`
}

// MintQuoteInput prices one capability version for one payer and one
// argument digest at the current terms.
type MintQuoteInput struct {
	CapabilityID    string
	InputSchemaHash string
	Identities
	ArgsDigest string
}

func (in MintQuoteInput) validate() error {
	if err := checkText("capability_id", in.CapabilityID, MaxCapabilityIDBytes, true); err != nil {
		return err
	}
	if err := checkDigest("input_schema_hash", in.InputSchemaHash); err != nil {
		return err
	}
	if err := checkDigest("args_digest", in.ArgsDigest); err != nil {
		return err
	}
	return in.Identities.validate()
}

// HashedTime is the only textual form of a hashed timestamp: UTC,
// second precision, a literal Z, no fractional seconds and no offset (ADR
// 020 sec. 5). Go's RFC3339 produces it; Python's isoformat does not.
func HashedTime(t time.Time) string {
	return t.UTC().Truncate(time.Second).Format("2006-01-02T15:04:05Z")
}

// lengthPrefixed is the encoding mctl-api already uses for approval intent
// hashes: <field>:<byte length>:<value>\n per field, after a version line.
func lengthPrefixed(version string, fields [][2]string) string {
	var b strings.Builder
	b.WriteString(version)
	b.WriteByte('\n')
	for _, f := range fields {
		b.WriteString(f[0])
		b.WriteByte(':')
		b.WriteString(strconv.Itoa(len(f[1])))
		b.WriteByte(':')
		b.WriteString(f[1])
		b.WriteByte('\n')
	}
	return b.String()
}

func digestOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// QuoteDigest is sha256 over the mctl-commerce-quote/v1 encoding of the quote
// (ADR 020 sec. 5). It is what idempotency compares and what an
// invocation must reproduce.
func QuoteDigest(q Quote) string {
	return digestOf(lengthPrefixed(quoteEncodingVersion, [][2]string{
		{"quote_id", q.QuoteID},
		{"terms_id", q.TermsID},
		{"terms_version", strconv.FormatInt(q.TermsVersion, 10)},
		{"capability_id", q.CapabilityID},
		{"input_schema_hash", q.InputSchemaHash},
		{"tenant_id", q.TenantID},
		{"payer_account_id", q.PayerAccountID},
		{"principal_id", q.PrincipalID},
		{"subject_principal_id", q.SubjectPrincipalID},
		{"delegation_grant_id", q.DelegationGrantID},
		{"execution_id", q.ExecutionID},
		{"args_digest", q.ArgsDigest},
		{"price_mode", q.PriceMode},
		{"currency", q.Price.Currency},
		{"amount_minor", strconv.FormatInt(q.Price.AmountMinor, 10)},
		{"funds_mode", q.FundsMode},
		{"expires_at", HashedTime(q.ExpiresAt)},
	}))
}

// TermsBinding is sha256 over the mctl-commerce-terms/v1 encoding: the price
// an approval binds (ADR 020 sec. 8). It has no quote id and no expiry, so
// an approval decided hours later still matches the quote minted after it.
func TermsBinding(t Terms, tenantID, payerAccountID string) string {
	return digestOf(lengthPrefixed(termsEncodingVersion, [][2]string{
		{"terms_id", t.TermsID},
		{"terms_version", strconv.FormatInt(t.TermsVersion, 10)},
		{"capability_id", t.CapabilityID},
		{"input_schema_hash", t.InputSchemaHash},
		{"tenant_id", tenantID},
		{"payer_account_id", payerAccountID},
		{"price_mode", t.PriceMode},
		{"currency", t.Price.Currency},
		{"amount_minor", strconv.FormatInt(t.Price.AmountMinor, 10)},
		{"funds_mode", t.FundsMode},
	}))
}

// Invocation is one accepted paid (or free-with-terms) capability call and
// the five facts about it (ADR 020 secs. 1 and 11).
type Invocation struct {
	SchemaVersion int    `json:"schema_version"`
	InvocationID  string `json:"invocation_id"`
	QuoteID       string `json:"quote_id"`
	QuoteDigest   string `json:"quote_digest"`
	// QuoteExpiresAt lets the reconciler refuse an accepted row whose quote
	// lapsed before anything was reserved (ADR 020 sec. 11).
	QuoteExpiresAt time.Time `json:"quote_expires_at"`
	TermsID        string    `json:"terms_id"`
	TermsVersion   int64     `json:"terms_version"`
	CapabilityID   string    `json:"capability_id"`
	ProviderID     string    `json:"provider_id"`
	Identities
	IdempotencyKey string `json:"idempotency_key"`
	ArgsDigest     string `json:"args_digest"`
	PriceMode      string `json:"price_mode"`
	Price          Money  `json:"price"`
	FundsMode      string `json:"funds_mode"`

	Phase            string `json:"phase"`
	ExecutionOutcome string `json:"execution_outcome"`
	UsageQuantity    *int64 `json:"usage_quantity,omitempty"`
	ChargeStatus     string `json:"charge_status"`
	PaymentStatus    string `json:"payment_status"`
	SettlementStatus string `json:"settlement_status"`
	ReasonCode       string `json:"reason_code,omitempty"`
	ApprovalID       string `json:"approval_id,omitempty"`
	ProviderOpKey    string `json:"provider_operation_key"`

	ReservationDeadline    *time.Time `json:"reservation_deadline,omitempty"`
	ReconciliationDeadline time.Time  `json:"reconciliation_deadline"`
	CreatedAt              time.Time  `json:"created_at"`
	UpdatedAt              time.Time  `json:"updated_at"`
	// FinalizedAt is set only when the phase became finalized; refused and
	// released rows carry their moment in updated_at.
	FinalizedAt *time.Time `json:"finalized_at,omitempty"`
	Version     int64      `json:"version"`
}

// ProviderOperationKey is the stable key a provider dedupes on (ADR 020
// sec. 6).
func ProviderOperationKey(invocationID string) string {
	return "mctl-op/v1:" + invocationID
}

// PaymentOperationKey derives the authorize/capture/void key (ADR 020 sec. 6).
func PaymentOperationKey(invocationID, operation string) string {
	return "mctl-pay/v1:" + invocationID + ":" + operation
}

// AcceptInvocationInput accepts a quoted invocation (ADR 020 sec. 7 step 6).
type AcceptInvocationInput struct {
	QuoteID        string
	QuoteDigest    string
	IdempotencyKey string
	Identities     Identities
	ArgsDigest     string
	ApprovalID     string
	// TermsBinding, when set, must equal the binding of the quote's terms
	// for this payer; this is how step 6 proves the approval covered this
	// price.
	TermsBinding string
}

var idempotencyKeyPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

func (in AcceptInvocationInput) validate() error {
	if err := checkText("quote_id", in.QuoteID, MaxIDBytes, true); err != nil {
		return err
	}
	if err := checkDigest("quote_digest", in.QuoteDigest); err != nil {
		return err
	}
	if !idempotencyKeyPattern.MatchString(in.IdempotencyKey) {
		return invalid("idempotency_key must be 1..%d of [A-Za-z0-9._:-]", MaxIdempotencyKey)
	}
	if err := checkDigest("args_digest", in.ArgsDigest); err != nil {
		return err
	}
	if err := checkText("approval_id", in.ApprovalID, MaxIDBytes, false); err != nil {
		return err
	}
	if in.TermsBinding != "" {
		if err := checkDigest("terms_binding", in.TermsBinding); err != nil {
			return err
		}
	}
	return in.Identities.validate()
}

// Transition is one append-only history row (ADR 020 sec. 11).
type Transition struct {
	Seq          int64     `json:"seq"`
	InvocationID string    `json:"invocation_id"`
	FromPhase    string    `json:"from_phase"`
	ToPhase      string    `json:"to_phase"`
	ReasonCode   string    `json:"reason_code,omitempty"`
	Actor        string    `json:"actor"`
	Note         string    `json:"note,omitempty"`
	RecordedAt   time.Time `json:"recorded_at"`
}

// TransitionInput moves an invocation from an expected phase to the next.
// The fields beside the phase are set only when the target phase defines
// them; a transition that does not match the current phase is rejected.
type TransitionInput struct {
	InvocationID  string
	ExpectedPhase string
	ToPhase       string
	ReasonCode    string
	Actor         string
	Note          string

	ExecutionOutcome    string
	UsageQuantity       *int64
	ChargeStatus        string
	PaymentStatus       string
	SettlementStatus    string
	ReservationDeadline *time.Time
}

// allowedTransitions is the state machine of ADR 020 sec. 11. A pair absent
// here is a phase conflict, never a silent write.
var allowedTransitions = map[string]map[string]bool{
	PhaseAccepted:       {PhaseRefused: true, PhaseReserved: true},
	PhaseReserved:       {PhaseDispatching: true, PhaseReleased: true},
	PhaseDispatching:    {PhaseDispatched: true, PhaseReleased: true, PhaseOutcomeUnknown: true},
	PhaseDispatched:     {PhaseFinalized: true, PhaseOutcomeUnknown: true},
	PhaseOutcomeUnknown: {PhaseFinalized: true},
}

// IsTerminal reports whether a phase admits no further transition.
func IsTerminal(phase string) bool {
	return phase == PhaseRefused || phase == PhaseReleased || phase == PhaseFinalized
}

func (in TransitionInput) validate() error {
	if err := checkText("invocation_id", in.InvocationID, MaxIDBytes, true); err != nil {
		return err
	}
	if err := checkText("actor", in.Actor, MaxIDBytes, true); err != nil {
		return err
	}
	if err := checkText("reason_code", in.ReasonCode, MaxIDBytes, false); err != nil {
		return err
	}
	if err := checkText("note", in.Note, MaxReasonBytes, false); err != nil {
		return err
	}
	if IsTerminal(in.ExpectedPhase) {
		return fmt.Errorf("%w: %s", ErrTerminal, in.ExpectedPhase)
	}
	if !allowedTransitions[in.ExpectedPhase][in.ToPhase] {
		return fmt.Errorf("%w: %s -> %s is not a transition", ErrPhaseConflict, in.ExpectedPhase, in.ToPhase)
	}
	if (in.ToPhase == PhaseRefused || in.ToPhase == PhaseReleased) && in.ReasonCode == "" {
		return invalid("reason_code is required for %s", in.ToPhase)
	}
	// Every one of the four facts is checked against its vocabulary on every
	// edge, not only on finalized: a typo from a programmatic caller must
	// never become a row in the ledger of record.
	for _, f := range []struct {
		name, value string
		allowed     []string
	}{
		{"execution_outcome", in.ExecutionOutcome, []string{OutcomeNotDispatched, OutcomeSucceeded, OutcomeFailed, OutcomeUnknown}},
		{"charge_status", in.ChargeStatus, []string{ChargeNone, ChargeReserved, ChargeCaptured, ChargeReleased}},
		{"payment_status", in.PaymentStatus, []string{PaymentNone, PaymentNotRequired, PaymentAuthorized, PaymentDenied, PaymentCaptured, PaymentVoided, PaymentUnknown}},
		{"settlement_status", in.SettlementStatus, []string{SettlementNotApplicable, SettlementPending, SettlementSettled, SettlementFailed}},
	} {
		if f.value == "" {
			continue
		}
		if !slices.Contains(f.allowed, f.value) {
			return invalid("%s %q is not one of %s", f.name, f.value, strings.Join(f.allowed, ", "))
		}
	}
	if in.ToPhase == PhaseFinalized {
		switch in.ExecutionOutcome {
		case OutcomeSucceeded, OutcomeFailed:
		default:
			return invalid("finalized requires execution_outcome succeeded or failed")
		}
		switch in.ChargeStatus {
		case ChargeCaptured, ChargeReleased:
		default:
			return invalid("finalized requires charge_status captured or released")
		}
		if in.UsageQuantity == nil {
			return invalid("finalized requires usage_quantity")
		}
	}
	if in.ToPhase == PhaseReserved && in.ReservationDeadline == nil {
		return invalid("reserved requires reservation_deadline")
	}
	if in.UsageQuantity != nil && *in.UsageQuantity < 0 {
		return invalid("usage_quantity must be >= 0")
	}
	return nil
}

// ListFilter scopes an invocation listing to one tenant (ADR 020 sec. 12).
type ListFilter struct {
	TenantID     string
	CapabilityID string
	Phase        string
	Since        time.Time
	Until        time.Time
	Limit        int
}
