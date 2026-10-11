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

import "time"

// Policy decision reference statuses.
const (
	PolicyNone        = "none"
	PolicyRecorded    = "recorded"
	PolicyMissing     = "missing"
	PolicyUnavailable = "unavailable"
)

// PolicyDecisionRef names the policy decision that covered an invocation. It
// is a reference read from the action approval, never a stored ledger column.
// "unavailable" means the approval could not be read, which is not the same
// as "none".
type PolicyDecisionRef struct {
	Status        string `json:"status"`
	ApprovalID    string `json:"approval_id,omitempty"`
	PolicyRuleID  string `json:"policy_rule_id,omitempty"`
	PolicyVersion string `json:"policy_version,omitempty"`
}

// Receipt is the ADR 020 sec. 12 projection of an invocation. It is an
// explicit allowlist, not an embedding of Invocation: a field added to
// Invocation later cannot reach a receipt by accident. It carries no
// idempotency key, argument digest, provider operation key, version or
// reservation reference, and no argument, result or payment proof.
type Receipt struct {
	SchemaVersion      int    `json:"schema_version"`
	InvocationID       string `json:"invocation_id"`
	QuoteID            string `json:"quote_id"`
	QuoteDigest        string `json:"quote_digest"`
	TermsID            string `json:"terms_id"`
	TermsVersion       int64  `json:"terms_version"`
	CapabilityID       string `json:"capability_id"`
	ProviderID         string `json:"provider_id"`
	TenantID           string `json:"tenant_id"`
	PayerAccountID     string `json:"payer_account_id"`
	PrincipalID        string `json:"principal_id"`
	SubjectPrincipalID string `json:"subject_principal_id"`
	DelegationGrantID  string `json:"delegation_grant_id,omitempty"`
	ExecutionID        string `json:"execution_id"`
	ApprovalID         string `json:"approval_id,omitempty"`
	PriceMode          string `json:"price_mode"`
	Price              Money  `json:"price"`
	FundsMode          string `json:"funds_mode"`
	Phase              string `json:"phase"`
	ReasonCode         string `json:"reason_code,omitempty"`

	ExecutionOutcome string `json:"execution_outcome"`
	UsageQuantity    *int64 `json:"usage_quantity,omitempty"`
	ChargeStatus     string `json:"charge_status"`
	PaymentStatus    string `json:"payment_status"`
	SettlementStatus string `json:"settlement_status"`

	QuoteExpiresAt         time.Time  `json:"quote_expires_at"`
	CreatedAt              time.Time  `json:"created_at"`
	UpdatedAt              time.Time  `json:"updated_at"`
	ReconciliationDeadline time.Time  `json:"reconciliation_deadline"`
	ReservationDeadline    *time.Time `json:"reservation_deadline,omitempty"`
	DispatchDeadline       *time.Time `json:"dispatch_deadline,omitempty"`
	FinalizedAt            *time.Time `json:"finalized_at,omitempty"`

	PolicyDecision PolicyDecisionRef `json:"policy_decision"`
}

// ReceiptOf projects an invocation and its policy decision reference.
func ReceiptOf(inv Invocation, policy PolicyDecisionRef) Receipt {
	return Receipt{
		SchemaVersion:          SchemaVersion,
		InvocationID:           inv.InvocationID,
		QuoteID:                inv.QuoteID,
		QuoteDigest:            inv.QuoteDigest,
		TermsID:                inv.TermsID,
		TermsVersion:           inv.TermsVersion,
		CapabilityID:           inv.CapabilityID,
		ProviderID:             inv.ProviderID,
		TenantID:               inv.TenantID,
		PayerAccountID:         inv.PayerAccountID,
		PrincipalID:            inv.PrincipalID,
		SubjectPrincipalID:     inv.SubjectPrincipalID,
		DelegationGrantID:      inv.DelegationGrantID,
		ExecutionID:            inv.ExecutionID,
		ApprovalID:             inv.ApprovalID,
		PriceMode:              inv.PriceMode,
		Price:                  inv.Price,
		FundsMode:              inv.FundsMode,
		Phase:                  inv.Phase,
		ReasonCode:             inv.ReasonCode,
		ExecutionOutcome:       inv.ExecutionOutcome,
		UsageQuantity:          inv.UsageQuantity,
		ChargeStatus:           inv.ChargeStatus,
		PaymentStatus:          inv.PaymentStatus,
		SettlementStatus:       inv.SettlementStatus,
		QuoteExpiresAt:         inv.QuoteExpiresAt,
		CreatedAt:              inv.CreatedAt,
		UpdatedAt:              inv.UpdatedAt,
		ReconciliationDeadline: inv.ReconciliationDeadline,
		ReservationDeadline:    inv.ReservationDeadline,
		DispatchDeadline:       inv.DispatchDeadline,
		FinalizedAt:            inv.FinalizedAt,
		PolicyDecision:         policy,
	}
}
