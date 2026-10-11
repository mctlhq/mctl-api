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
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"
)

func fullInvocation() Invocation {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	qty := int64(3)
	return Invocation{
		SchemaVersion: SchemaVersion, InvocationID: "inv_1", QuoteID: "cq_1", QuoteDigest: "sha256:x",
		QuoteExpiresAt: now, TermsID: "ctm_1", TermsVersion: 2, CapabilityID: "mctl://c", ProviderID: "p",
		Identities: Identities{TenantID: "acme", PrincipalID: "prn_a", SubjectPrincipalID: "prn_b",
			DelegationGrantID: "dg_1", PayerAccountID: "acct", ExecutionID: "we_1"},
		IdempotencyKey: "secret-key", ArgsDigest: "sha256:args", PriceMode: PriceModePerCall,
		Price: Money{Currency: "EUR", AmountMinor: 12}, FundsMode: FundsModeSimulated,
		Phase: PhaseFinalized, ExecutionOutcome: OutcomeSucceeded, UsageQuantity: &qty,
		ChargeStatus: ChargeCaptured, PaymentStatus: PaymentCaptured, SettlementStatus: SettlementSettled,
		ReasonCode: "r", ApprovalID: "aar_1", ProviderOpKey: "mctl-op/v1:inv_1",
		ReservationDeadline: &now, ReconciliationDeadline: now, CreatedAt: now, UpdatedAt: now,
		FinalizedAt: &now, Version: 9, DispatchDeadline: &now,
	}
}

func TestReceiptOf_KeySetIsTheAllowlist(t *testing.T) {
	rc := ReceiptOf(fullInvocation(), PolicyDecisionRef{Status: PolicyRecorded, ApprovalID: "aar_1", PolicyRuleID: "r", PolicyVersion: "v"})
	raw, err := json.Marshal(rc)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var got []string
	for k := range doc {
		got = append(got, k)
	}
	sort.Strings(got)
	want := strings.Fields("approval_id capability_id charge_status created_at delegation_grant_id dispatch_deadline execution_id execution_outcome finalized_at funds_mode invocation_id payer_account_id payment_status phase policy_decision price price_mode principal_id provider_id quote_digest quote_expires_at quote_id reason_code reconciliation_deadline reservation_deadline schema_version settlement_status subject_principal_id tenant_id terms_id terms_version updated_at usage_quantity")
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("receipt keys\n got %v\nwant %v", got, want)
	}
	for _, banned := range []string{"idempotency_key", "args_digest", "provider_operation_key", "authorization_id", "capture_id", "external_ref", "secret-key"} {
		if strings.Contains(string(raw), banned) {
			t.Errorf("receipt leaks %q: %s", banned, raw)
		}
	}
}

func TestReceiptOf_AmountsAreIntegers(t *testing.T) {
	rc := ReceiptOf(fullInvocation(), PolicyDecisionRef{Status: PolicyNone})
	raw, _ := json.Marshal(rc)
	s := string(raw)
	for _, frag := range []string{`"amount_minor":12}`, `"terms_version":2`, `"usage_quantity":3`, `"schema_version":1`} {
		if !strings.Contains(s, frag) {
			t.Errorf("missing integer fragment %s in %s", frag, s)
		}
	}
	if rc.SchemaVersion != SchemaVersion {
		t.Fatalf("schema_version = %d", rc.SchemaVersion)
	}
}
