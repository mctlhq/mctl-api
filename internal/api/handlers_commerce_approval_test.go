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

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/commerce"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// commerceTestExecutionID is the execution every fixture quote is minted for.
const commerceTestExecutionID = "we_01JZ8Q0000000000000000000C"

// approval stores an action approval requested by requestedBy for
// executionID and returns its id; consumed takes it through approve and
// consume, as the gateway does after accept. The fixture gains a work-items
// store on first use, and the approval is deleted with the test.
func (f *commerceFixture) approval(t *testing.T, requestedBy, executionID string, consumed bool) string {
	t.Helper()
	ctx := context.Background()
	if f.h.opts.WorkItems == nil {
		items, err := workitems.NewStore(ctx, os.Getenv("TEST_DATABASE_URL"))
		if err != nil {
			t.Fatalf("workitems.NewStore: %v", err)
		}
		t.Cleanup(items.Close)
		f.h.opts.WorkItems = items
	}
	intent := workitems.ActionIntent{
		ExecutionID: executionID, ActionKind: "mcp.tool.call", Target: "pilot",
		ArgsDigest: commerceTestArgsDigest, PolicyRuleID: "paid-approve", PolicyVersion: "test/v1",
	}
	a, _, err := f.h.opts.WorkItems.CreateActionApproval(ctx, workitems.ActionApprovalInput{
		ActionIntent: intent, RequestedBy: requestedBy,
		IdempotencyKey: fmt.Sprintf("%s-%d", strings.ToLower(t.Name()), time.Now().UnixNano()),
		ExpiresAt:      time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateActionApproval: %v", err)
	}
	t.Cleanup(func() { _, _ = f.pool.Exec(ctx, `DELETE FROM action_approval_requests WHERE id = $1`, a.ID) })
	if consumed {
		if _, err := f.h.opts.WorkItems.DecideActionApproval(ctx, workitems.ActionDecisionInput{
			ID: a.ID, DecidedBy: "github:approver", Decision: workitems.DecisionApprove, Reason: "test",
		}); err != nil {
			t.Fatalf("DecideActionApproval: %v", err)
		}
		if _, err := f.h.opts.WorkItems.ConsumeActionApproval(ctx, a.ID, workitems.IntentHash(intent)); err != nil {
			t.Fatalf("ConsumeActionApproval: %v", err)
		}
	}
	return a.ID
}

// mctl-agents#626 item 6: approval_id is caller input. An approval binds
// only the call that requested it: same requesting principal, same
// execution. Anything else is refused before a row exists, with one answer
// for "not yours" and "does not exist".
func TestCommerceAccept_ApprovalMustBelongToTheCall(t *testing.T) {
	f := newCommerceFixture(t)
	f.publish(t)
	owner := tenantUser(t, "acme-owner", "acme", "prn_owner")
	dev := tenantUser(t, "acme-dev", "acme", "prn_dev")
	acceptWith := func(approval, key string) (int, string) {
		_, q := f.mint(t, owner, "acme", nil)
		if q == nil {
			t.Fatal("mint failed")
		}
		rec := f.call(t, owner, "POST", "/api/v1/commerce/tenants/acme/invocations", map[string]any{
			"quote_id": q.QuoteID, "quote_digest": q.QuoteDigest, "idempotency_key": key, "args_digest": q.ArgsDigest,
			"execution_id": q.ExecutionID, "approval_id": approval,
		}, map[string]string{"tenant": "acme"}, f.h.AcceptCommerceInvocation)
		return rec.Code, rec.Body.String()
	}
	rowFor := func(key string) bool {
		rec := f.call(t, owner, "GET", "/api/v1/commerce/tenants/acme/invocations?idempotency_key="+key, nil,
			map[string]string{"tenant": "acme"}, f.h.ListCommerceInvocations)
		if rec.Code != http.StatusOK {
			t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
		}
		return strings.Contains(rec.Body.String(), `"invocation_id"`)
	}

	refused := map[string]string{
		"requested by another member": f.approval(t, principalOf(dev), commerceTestExecutionID, false),
		"for another execution":       f.approval(t, principalOf(owner), "we_01JZ8Q0000000000000000000D", false),
		"that does not exist":         "aar_" + strings.ToLower(t.Name()) + "_missing",
	}
	var bodies []string
	for name, approval := range refused {
		key := "k-" + strings.ReplaceAll(name, " ", "-")
		code, body := acceptWith(approval, key)
		if code != http.StatusConflict || !strings.Contains(body, `"policy-denied"`) || !strings.Contains(body, "does not belong") {
			t.Fatalf("approval %s: %d %s", name, code, body)
		}
		if rowFor(key) {
			t.Fatalf("approval %s: a row was created", name)
		}
		bodies = append(bodies, body)
	}
	if bodies[0] != bodies[1] || bodies[1] != bodies[2] {
		t.Fatalf("refusals differ, which tells existence apart: %q", bodies)
	}

	// The caller's own approval for this execution is accepted whatever its
	// state: the gateway consumes it after accept, so a replayed accept
	// names an approval that is already consumed.
	own := f.approval(t, principalOf(owner), commerceTestExecutionID, true)
	if code, body := acceptWith(own, "k-own"); code != http.StatusCreated {
		t.Fatalf("own approval: %d %s", code, body)
	}
}

func TestCommerceAccept_UnreadableApprovalIsUnavailableNotRefused(t *testing.T) {
	f := newCommerceFixture(t)
	f.publish(t)
	owner := tenantUser(t, "acme-owner", "acme", "prn_owner")
	_, q := f.mint(t, owner, "acme", nil)
	rec := f.call(t, owner, "POST", "/api/v1/commerce/tenants/acme/invocations", map[string]any{
		"quote_id": q.QuoteID, "quote_digest": q.QuoteDigest, "idempotency_key": "k-unread", "args_digest": q.ArgsDigest,
		"execution_id": q.ExecutionID, "approval_id": "aar_any",
	}, map[string]string{"tenant": "acme"}, f.h.AcceptCommerceInvocation)
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "approval-unavailable") {
		t.Fatalf("no work-items store: %d %s", rec.Code, rec.Body.String())
	}
	// Without an approval the store is not needed.
	if rec, acc := f.accept(t, owner, "acme", q, "k-plain"); acc == nil {
		t.Fatalf("plain accept: %d %s", rec.Code, rec.Body.String())
	}
}

// The receipt's policy decision reference comes from the invocation's action
// approval: recorded carries its rule id and version, and a vanished approval
// is "missing", never "none".
func TestCommerceReceipt_PolicyDecisionRecordedAndMissing(t *testing.T) {
	f := newCommerceFixture(t)
	f.publish(t)
	owner := tenantUser(t, "acme-owner", "acme", "prn_owner")
	receipt := func(invID string) commerce.Receipt {
		rec := f.call(t, owner, "GET", "/api/v1/commerce/tenants/acme/invocations/"+invID+"/receipt", nil,
			map[string]string{"tenant": "acme", "invocation_id": invID}, f.h.GetCommerceReceipt)
		if rec.Code != http.StatusOK {
			t.Fatalf("receipt: %d %s", rec.Code, rec.Body.String())
		}
		var rc commerce.Receipt
		if err := json.Unmarshal(rec.Body.Bytes(), &rc); err != nil {
			t.Fatal(err)
		}
		return rc
	}
	acceptWith := func(approval, key string) string {
		_, q := f.mint(t, owner, "acme", nil)
		if q == nil {
			t.Fatal("mint failed")
		}
		rec := f.call(t, owner, "POST", "/api/v1/commerce/tenants/acme/invocations", map[string]any{
			"quote_id": q.QuoteID, "quote_digest": q.QuoteDigest, "idempotency_key": key, "args_digest": q.ArgsDigest,
			"execution_id": q.ExecutionID, "approval_id": approval,
		}, map[string]string{"tenant": "acme"}, f.h.AcceptCommerceInvocation)
		if rec.Code != http.StatusCreated {
			t.Fatalf("accept: %d %s", rec.Code, rec.Body.String())
		}
		var res acceptInvocationResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
			t.Fatal(err)
		}
		return res.InvocationID
	}

	approval := f.approval(t, principalOf(owner), commerceTestExecutionID, true)
	pd := receipt(acceptWith(approval, "k-pd-recorded")).PolicyDecision
	if pd.Status != commerce.PolicyRecorded || pd.ApprovalID != approval ||
		pd.PolicyRuleID != "paid-approve" || pd.PolicyVersion != "test/v1" {
		t.Fatalf("recorded: %+v", pd)
	}

	gone := f.approval(t, principalOf(owner), commerceTestExecutionID, true)
	id := acceptWith(gone, "k-pd-missing")
	if _, err := f.pool.Exec(context.Background(), `DELETE FROM action_approval_requests WHERE id = $1`, gone); err != nil {
		t.Fatal(err)
	}
	pd = receipt(id).PolicyDecision
	if pd.Status != commerce.PolicyMissing || pd.ApprovalID != gone {
		t.Fatalf("missing: %+v", pd)
	}
}
