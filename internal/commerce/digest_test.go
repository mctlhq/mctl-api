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
	"strings"
	"testing"
	"time"
)

// The golden vectors of ADR 020 secs. 5 and 8. They were computed by the
// Python reference in mctl-agents; C4's Python test pins the same values,
// so the two implementations can never drift apart silently.
const (
	goldenQuoteDigest  = "sha256:1a7b37d7215a2d02d9160f0afe49310e803eb2515f3745f0afb77995f8069131"
	goldenTermsBinding = "sha256:edefb0ce2c0ce7b46abb82aab173268568657ee2ae9fd32af8e8eac54e5514e1"
	goldenArgsDigest   = "sha256:73fd22bf1a31b2661710f8e3413afb2705c876302e6cbf8a112aed3317130c8c"
)

func goldenTerms() Terms {
	return Terms{
		TermsID:         "ctm_01JZ8PZ0000000000000000000",
		TermsVersion:    3,
		CapabilityID:    "mctl://mcp-remote/pilot-provider/lookup_status",
		InputSchemaHash: "sha256:" + strings.Repeat("ab", 32),
		PriceMode:       PriceModePerSuccessfulCall,
		Price:           Money{Currency: "EUR", AmountMinor: 12},
		FundsMode:       FundsModeSimulated,
	}
}

func goldenQuote() Quote {
	t := goldenTerms()
	return Quote{
		QuoteID:         "cq_01JZ8Q3K7W5V4X2Y1Z0A9B8C7D",
		TermsID:         t.TermsID,
		TermsVersion:    t.TermsVersion,
		CapabilityID:    t.CapabilityID,
		InputSchemaHash: t.InputSchemaHash,
		Identities: Identities{
			TenantID:           "acme",
			PayerAccountID:     "acct_tenant_acme",
			PrincipalID:        "prn_01JZ8Q0000000000000000000A",
			SubjectPrincipalID: "prn_01JZ8Q0000000000000000000B",
			DelegationGrantID:  "",
			ExecutionID:        "we_01JZ8Q0000000000000000000C",
		},
		ArgsDigest: goldenArgsDigest,
		PriceMode:  t.PriceMode,
		Price:      t.Price,
		FundsMode:  t.FundsMode,
		ExpiresAt:  time.Date(2026, 10, 11, 12, 5, 0, 0, time.UTC),
	}
}

func TestQuoteDigestGoldenVector(t *testing.T) {
	if got := QuoteDigest(goldenQuote()); got != goldenQuoteDigest {
		t.Fatalf("quote_digest = %s, want %s", got, goldenQuoteDigest)
	}
}

func TestTermsBindingGoldenVector(t *testing.T) {
	if got := TermsBinding(goldenTerms(), "acme", "acct_tenant_acme"); got != goldenTermsBinding {
		t.Fatalf("terms_binding = %s, want %s", got, goldenTermsBinding)
	}
}

func TestQuoteDigestIsSensitiveToEveryField(t *testing.T) {
	base := goldenQuote()
	mutations := map[string]func(*Quote){
		"quote_id":             func(q *Quote) { q.QuoteID += "x" },
		"terms_version":        func(q *Quote) { q.TermsVersion++ },
		"capability_id":        func(q *Quote) { q.CapabilityID += "/x" },
		"input_schema_hash":    func(q *Quote) { q.InputSchemaHash = "sha256:" + strings.Repeat("cd", 32) },
		"tenant_id":            func(q *Quote) { q.TenantID = "acme2" },
		"payer_account_id":     func(q *Quote) { q.PayerAccountID = "acct_other" },
		"principal_id":         func(q *Quote) { q.PrincipalID = q.SubjectPrincipalID },
		"subject_principal_id": func(q *Quote) { q.SubjectPrincipalID = q.PrincipalID },
		"delegation_grant_id":  func(q *Quote) { q.DelegationGrantID = "dg_1" },
		"execution_id":         func(q *Quote) { q.ExecutionID = "we_other" },
		"args_digest":          func(q *Quote) { q.ArgsDigest = "sha256:" + strings.Repeat("00", 32) },
		"price_mode":           func(q *Quote) { q.PriceMode = PriceModePerCall },
		"currency":             func(q *Quote) { q.Price.Currency = "USD" },
		"amount_minor":         func(q *Quote) { q.Price.AmountMinor = 13 },
		"funds_mode":           func(q *Quote) { q.FundsMode = FundsModeLive },
		"expires_at":           func(q *Quote) { q.ExpiresAt = q.ExpiresAt.Add(time.Second) },
	}
	for name, mutate := range mutations {
		q := base
		mutate(&q)
		if QuoteDigest(q) == goldenQuoteDigest {
			t.Errorf("mutating %s did not change the digest", name)
		}
	}
}

// Length prefixing is what keeps "a"+"bc" apart from "ab"+"c": a separator
// based encoding would collide here.
func TestLengthPrefixedEncodingHasNoAmbiguity(t *testing.T) {
	a := lengthPrefixed("v", [][2]string{{"x", "a"}, {"y", "bc"}})
	b := lengthPrefixed("v", [][2]string{{"x", "ab"}, {"y", "c"}})
	if a == b {
		t.Fatal("encodings collide")
	}
	want := "v\nx:1:a\ny:2:bc\n"
	if a != want {
		t.Fatalf("encoding = %q, want %q", a, want)
	}
}

func TestHashedTimeIsSecondPrecisionUTCWithZ(t *testing.T) {
	loc := time.FixedZone("plus2", 2*3600)
	in := time.Date(2026, 10, 11, 14, 5, 0, 987654321, loc)
	if got := HashedTime(in); got != "2026-10-11T12:05:00Z" {
		t.Fatalf("HashedTime = %q", got)
	}
}

func TestNewULIDShape(t *testing.T) {
	id, err := newULID(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(id) != 26 {
		t.Fatalf("ulid length %d: %q", len(id), id)
	}
	for _, c := range id {
		if !strings.ContainsRune("0123456789ABCDEFGHJKMNPQRSTVWXYZ", c) {
			t.Fatalf("ulid has non-Crockford char %q in %q", c, id)
		}
	}
	if id[0] > '7' {
		t.Fatalf("ulid first char must encode 2 zero bits: %q", id)
	}
	if other, _ := newULID(time.Now()); other == id {
		t.Fatal("two ulids collided")
	}
}

func TestFundsModeLiveIsRefused(t *testing.T) {
	in := PublishTermsInput{
		CapabilityID:    "mctl://x/y/z",
		InputSchemaHash: "sha256:" + strings.Repeat("ab", 32),
		ProviderID:      "p",
		PriceMode:       PriceModePerCall,
		Price:           Money{Currency: "EUR", AmountMinor: 1},
		FundsMode:       FundsModeLive,
		QuoteTTLSeconds: 60,
		EffectiveFrom:   time.Now(),
		PublishedBy:     "prn_x",
	}
	if err := in.validate(); err == nil || !strings.Contains(err.Error(), "live funds") {
		t.Fatalf("live funds not refused: %v", err)
	}
}

func TestValidateRejectsUnknownCurrencyAndFloats(t *testing.T) {
	m := Money{Currency: "XXX", AmountMinor: 1}
	if err := m.validate("price"); err == nil {
		t.Fatal("unknown currency accepted")
	}
	if _, ok := CurrencyExponent("JPY"); !ok {
		t.Fatal("JPY must be in the table")
	}
}

func TestTransitionTable(t *testing.T) {
	ok := TransitionInput{InvocationID: "inv_1", Actor: "a", ExpectedPhase: PhaseAccepted, ToPhase: PhaseRefused, ReasonCode: ReasonQuoteExpired}
	if err := ok.validate(); err != nil {
		t.Fatalf("accepted->refused: %v", err)
	}
	bad := ok
	bad.ToPhase = PhaseFinalized
	if err := bad.validate(); err == nil {
		t.Fatal("accepted->finalized accepted")
	}
	noReason := ok
	noReason.ReasonCode = ""
	if err := noReason.validate(); err == nil {
		t.Fatal("refused without reason_code accepted")
	}
	term := ok
	term.ExpectedPhase = PhaseFinalized
	if err := term.validate(); err == nil {
		t.Fatal("transition out of a terminal phase accepted")
	}
	qty := int64(1)
	fin := TransitionInput{InvocationID: "inv_1", Actor: "a", ExpectedPhase: PhaseDispatched, ToPhase: PhaseFinalized,
		ExecutionOutcome: OutcomeSucceeded, ChargeStatus: ChargeCaptured, UsageQuantity: &qty}
	if err := fin.validate(); err != nil {
		t.Fatalf("dispatched->finalized: %v", err)
	}
	fin.ExecutionOutcome = OutcomeUnknown
	if err := fin.validate(); err == nil {
		t.Fatal("finalized with unknown outcome accepted")
	}
}
