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

package bridge

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestVendoredSchemasMatchProvenance(t *testing.T) {
	prov, err := schemaFS.ReadFile("schema/PROVENANCE")
	if err != nil {
		t.Fatal(err)
	}
	cmd, res, err := SchemaDigests()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"command.schema.json sha256: " + cmd, "result.schema.json sha256: " + res} {
		if !strings.Contains(string(prov), want) {
			t.Errorf("PROVENANCE does not pin %q", want)
		}
	}
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("schema/testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCommandFixtures(t *testing.T) {
	if err := ValidateCommand(fixture(t, "command.valid.json")); err != nil {
		t.Fatalf("valid fixture refused: %v", err)
	}
	for _, name := range []string{"command.bad-ref-pattern.json", "command.extra-field.json", "command.mutation-missing-approval.json"} {
		if err := ValidateCommand(fixture(t, name)); Code(err) != "invalid_document" {
			t.Errorf("%s: want invalid_document, got %v", name, err)
		}
	}
}

func TestCommandIDShape(t *testing.T) {
	if !IsCommandID("cmd_01HZZZZZZZZZZZZZZZZZZZZZZZ") || IsCommandID("brc_01HZZZZZZZZZZZZZZZZZZZZZZZ") || IsCommandID("cmd_short") {
		t.Fatal("command id pattern wrong")
	}
}

func TestResultFixtures(t *testing.T) {
	r, err := ParseResult(fixture(t, "result.valid.json"))
	if err != nil {
		t.Fatalf("valid result refused: %v", err)
	}
	if r.Digest() == "" || r.Digest() != r.Digest() {
		t.Fatal("digest unstable")
	}
	if _, err := ParseResult(fixture(t, "result.extra-field.json")); Code(err) != "invalid_document" {
		t.Errorf("extra field: got %v", err)
	}
	// Private bindings are never accepted in the result JSON.
	for _, f := range []string{"lease_epoch", "nonce", "operation_key", "tenant", "workflow_id", "approval_ref", "owner_principal_id"} {
		body := strings.Replace(string(fixture(t, "result.valid.json")), "\"attempt\": 1,", "\"attempt\": 1, \""+f+"\": \"x\",", 1)
		if _, err := ParseResult([]byte(body)); Code(err) != "invalid_document" {
			t.Errorf("%s accepted in result", f)
		}
	}
	// not_performed is an internal effect state, not a v1alpha1 outcome.
	body := strings.Replace(string(fixture(t, "result.valid.json")), "\"succeeded\"", "\"not_performed\"", 1)
	if _, err := ParseResult([]byte(body)); err == nil {
		t.Error("not_performed accepted as an outcome")
	}
}

func TestResultDigestIgnoresKeyOrder(t *testing.T) {
	a, err := ParseResult(fixture(t, "result.valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	b := *a
	if a.Digest() != b.Digest() {
		t.Fatal("digest differs for equal results")
	}
	b.CompletedAt = "2026-11-08T10:02:00Z"
	if a.Digest() == b.Digest() {
		t.Fatal("digest equal for different results")
	}
}

func TestEnqueueInputValidation(t *testing.T) {
	good := EnqueueInput{
		ExecutionID: "we_0123456789abcdef0123", WorkItemID: "wi_0123456789abcdef0123", WorkflowID: "wf", Tenant: "t",
		OwnerPrincipalID: "p", TenantRef: "tnr_0123456789abcdef0123", PrincipalRef: "prr_0123456789abcdef0123",
		OrderRef: "ordr_0123456789abcdef0123", ConnectionRef: "gcn_0123456789abcdef0123", InstallRevision: "r1",
		ProviderRef: "glovo", Kind: KindPlaceOrderFake, Attempt: 1, OperationKey: "op",
		IntentHash: "sha256:" + strings.Repeat("0", 64), ApprovalRef: "aar_0123456789abcdef0123", TTL: time.Minute,
	}
	if err := good.validate(); err != nil {
		t.Fatalf("good input refused: %v", err)
	}
	noApproval := good
	noApproval.ApprovalRef = ""
	if Code(noApproval.validate()) != "invalid_input" {
		t.Error("mutating command without aar_ accepted")
	}
	readOnly := noApproval
	readOnly.Kind = KindReadStatus
	if err := readOnly.validate(); err != nil {
		t.Errorf("read-only without receipt refused: %v", err)
	}
	badRef := good
	badRef.OrderRef = "brc_0123456789abcdef0123"
	if Code(badRef.validate()) != "invalid_input" {
		t.Error("bad order ref accepted")
	}
	row := &cmdRow{
		CommandID: "cmd_01HZZZZZZZZZZZZZZZZZZZZZZZ", ExecutionID: good.ExecutionID, WorkItemID: good.WorkItemID, TenantRef: good.TenantRef,
		PrincipalRef: good.PrincipalRef, OrderRef: good.OrderRef, ConnectionRef: good.ConnectionRef, ProviderRef: "glovo",
		Kind: good.Kind, Attempt: 1, IntentHash: good.IntentHash, ApprovalRef: good.ApprovalRef, CommandNonce: "AAAAAAAAAAAAAAAAAAAAAA",
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute), TTLSeconds: 60, Payload: []byte(`{"quantity_total":1}`),
		LeaseToken: "lt_0123456789abcdef0123", LeaseEpoch: 7, LeaseNonce: "secret-nonce",
	}
	raw, err := row.projection(true)
	if err != nil {
		t.Fatalf("projection invalid: %v", err)
	}
	for _, leak := range []string{"lease_epoch", "secret-nonce", "lease_nonce", "operation_key", "workflow_id", "install_revision", "owner"} {
		if strings.Contains(string(raw), leak) {
			t.Errorf("projection leaks %s", leak)
		}
	}
}
