package workitems

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// agentPrincipal and storeTestExecution scope this package's approvals: the
// api package shares the database, requests as service:mctl-agent with the
// same idempotency keys, and cleans up only its own rows, so this one must
// neither collide with its keys nor wipe them.
const (
	agentPrincipal     = "service:workitems-store-test"
	storeTestExecution = "exec-1"
)

func approvalInput(s *Store, key string) ActionApprovalInput {
	return ActionApprovalInput{
		ActionIntent: ActionIntent{
			ExecutionID:   storeTestExecution,
			ActionKind:    "github.merge_pr",
			Target:        "mctlhq/mctl-api#1",
			ArgsDigest:    "sha256:args",
			PolicyRuleID:  "merge-needs-human",
			PolicyVersion: "v3",
			ArtifactHash:  "sha256:diff",
		},
		RequestedBy:    agentPrincipal,
		IdempotencyKey: key,
		ExpiresAt:      s.now().Add(time.Hour),
	}
}

func createApproval(t *testing.T, s *Store, in ActionApprovalInput) *ActionApprovalRequest {
	t.Helper()
	a, created, err := s.CreateActionApproval(context.Background(), in)
	if err != nil || !created {
		t.Fatalf("create: %v %v", created, err)
	}
	return a
}

func approved(t *testing.T, s *Store, key string) *ActionApprovalRequest {
	t.Helper()
	a := createApproval(t, s, approvalInput(s, key))
	a, err := s.DecideActionApproval(context.Background(), ActionDecisionInput{ID: a.ID, DecidedBy: "github:root", Decision: DecisionApprove})
	if err != nil || a.State != ApprovalApproved {
		t.Fatalf("approve: %+v %v", a, err)
	}
	return a
}

func TestIntentHashIsCanonicalAndCoversEveryField(t *testing.T) {
	base := approvalInput(&Store{now: time.Now}, "k").ActionIntent
	h := IntentHash(base)
	if !strings.HasPrefix(h, "sha256:") || len(h) != len("sha256:")+64 || IntentHash(base) != h {
		t.Fatalf("hash = %s", h)
	}
	// A known vector, so a client in another language can check itself.
	vector := ActionIntent{ExecutionID: "e", ActionKind: "k", Target: "t", ArgsDigest: "a", PolicyRuleID: "r", PolicyVersion: "v"}
	// printf 'mctl-action-intent/v1\nexecution_id:1:e\naction_kind:1:k\ntarget:1:t\nargs_digest:1:a\npolicy_rule_id:1:r\npolicy_version:1:v\nartifact_hash:0:\nwork_item_id:0:\n' | shasum -a 256
	if got := IntentHash(vector); got != "sha256:28c2d880c05722c10c09828b57160cdeccef1375fbf5a89982513c877e8a0df2" {
		t.Fatalf("vector hash = %s", got)
	}
	for name, mutate := range map[string]func(*ActionIntent){
		"execution_id":   func(i *ActionIntent) { i.ExecutionID += "x" },
		"action_kind":    func(i *ActionIntent) { i.ActionKind += "x" },
		"target":         func(i *ActionIntent) { i.Target += "x" },
		"args_digest":    func(i *ActionIntent) { i.ArgsDigest += "x" },
		"policy_rule_id": func(i *ActionIntent) { i.PolicyRuleID += "x" },
		"policy_version": func(i *ActionIntent) { i.PolicyVersion += "x" },
		"artifact_hash":  func(i *ActionIntent) { i.ArtifactHash += "x" },
		"work_item_id":   func(i *ActionIntent) { i.WorkItemID += "x" },
		// Moving bytes between adjacent fields changes the hash: the
		// length prefix makes the encoding unambiguous.
		"shifted boundary": func(i *ActionIntent) { i.ActionKind += i.Target[:1]; i.Target = i.Target[1:] },
	} {
		in := base
		mutate(&in)
		if IntentHash(in) == h {
			t.Errorf("%s does not change the hash", name)
		}
	}
}

func TestCreateActionApprovalIsIdempotentPerRequesterAndKey(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	in := approvalInput(s, "k-1")
	a := createApproval(t, s, in)
	if !strings.HasPrefix(a.ID, ActionApprovalIDPrefix) || a.State != ApprovalPending || a.RequestedBy != agentPrincipal ||
		a.IntentHash != IntentHash(in.ActionIntent) || a.SchemaVersion != ActionApprovalSchemaVersion {
		t.Fatalf("created = %+v", a)
	}

	// Same key, same intent: the stored request, even with another expiry
	// and a correct client-sent hash.
	again := in
	again.ExpiresAt = in.ExpiresAt.Add(time.Minute)
	again.IntentHash = a.IntentHash
	got, created, err := s.CreateActionApproval(ctx, again)
	if err != nil || created || got.ID != a.ID {
		t.Fatalf("replay = %+v %v %v", got, created, err)
	}
	// Same key, different intent: refused, nothing stored.
	drift := in
	drift.Target = "mctlhq/mctl-api#2"
	if _, _, err := s.CreateActionApproval(ctx, drift); !errors.Is(err, ErrApprovalIdempotencyConflict) {
		t.Fatalf("drift = %v", err)
	}
	// The key is per requester: another requester's same key is its own.
	other := in
	other.RequestedBy = "service:other"
	if b := createApproval(t, s, other); b.ID == a.ID {
		t.Fatal("another requester's key resolved to this request")
	}
	list, err := s.ActionApprovals(ctx, ActionApprovalFilter{ExecutionID: in.ExecutionID})
	if err != nil || len(list) != 2 {
		t.Fatalf("list = %d %v", len(list), err)
	}
}

func TestCreateActionApprovalValidates(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	w := open(t, s, CreateInput{})
	cases := map[string]func(*ActionApprovalInput){
		"no execution":      func(i *ActionApprovalInput) { i.ExecutionID = "" },
		"no action kind":    func(i *ActionApprovalInput) { i.ActionKind = " " },
		"no target":         func(i *ActionApprovalInput) { i.Target = "" },
		"no args digest":    func(i *ActionApprovalInput) { i.ArgsDigest = "" },
		"no policy rule":    func(i *ActionApprovalInput) { i.PolicyRuleID = "" },
		"no policy version": func(i *ActionApprovalInput) { i.PolicyVersion = "" },
		"no key":            func(i *ActionApprovalInput) { i.IdempotencyKey = "" },
		"no requester":      func(i *ActionApprovalInput) { i.RequestedBy = "" },
		"long target":       func(i *ActionApprovalInput) { i.Target = strings.Repeat("t", MaxApprovalTargetBytes+1) },
		"long kind":         func(i *ActionApprovalInput) { i.ActionKind = strings.Repeat("k", MaxApprovalFieldBytes+1) },
		"bad work item id":  func(i *ActionApprovalInput) { i.WorkItemID = "nope" },
		"unknown work item": func(i *ActionApprovalInput) { i.WorkItemID = WorkItemIDPrefix + "missing" },
		"no expiry":         func(i *ActionApprovalInput) { i.ExpiresAt = time.Time{} },
		"expired":           func(i *ActionApprovalInput) { i.ExpiresAt = s.now().Add(-time.Second) },
		"too far":           func(i *ActionApprovalInput) { i.ExpiresAt = s.now().Add(MaxApprovalTTL + time.Minute) },
	}
	for name, mutate := range cases {
		in := approvalInput(s, "k-"+name)
		mutate(&in)
		if _, _, err := s.CreateActionApproval(ctx, in); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	in := approvalInput(s, "k-hash")
	in.IntentHash = "sha256:" + strings.Repeat("0", 64)
	if _, _, err := s.CreateActionApproval(ctx, in); !errors.Is(err, ErrApprovalIntentHash) {
		t.Errorf("wrong hash: %v", err)
	}
	// A real work item binds, and changes the hash.
	in = approvalInput(s, "k-wi")
	in.WorkItemID = w.ID
	a := createApproval(t, s, in)
	if a.WorkItemID != w.ID || a.IntentHash == IntentHash(approvalInput(s, "").ActionIntent) {
		t.Fatalf("bound = %+v", a)
	}
}

func TestActionApprovalRefusesSecretsInText(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	token := "ghp_" + strings.Repeat("a", 36)
	for name, mutate := range map[string]func(*ActionApprovalInput){
		"execution_id":    func(i *ActionApprovalInput) { i.ExecutionID = token },
		"action_kind":     func(i *ActionApprovalInput) { i.ActionKind = token },
		"target":          func(i *ActionApprovalInput) { i.Target = "https://hooks.internal/x?token=" + token },
		"args_digest":     func(i *ActionApprovalInput) { i.ArgsDigest = token },
		"policy_rule_id":  func(i *ActionApprovalInput) { i.PolicyRuleID = token },
		"policy_version":  func(i *ActionApprovalInput) { i.PolicyVersion = token },
		"artifact_hash":   func(i *ActionApprovalInput) { i.ArtifactHash = token },
		"idempotency_key": func(i *ActionApprovalInput) { i.IdempotencyKey = token },
	} {
		in := approvalInput(s, "k-secret-"+name)
		mutate(&in)
		if _, _, err := s.CreateActionApproval(ctx, in); !errors.Is(err, ErrSecretInText) {
			t.Errorf("%s: err = %v, want ErrSecretInText", name, err)
		}
	}
	if list, err := s.ActionApprovals(ctx, ActionApprovalFilter{ExecutionID: storeTestExecution}); err != nil || len(list) != 0 {
		t.Fatalf("a refused request was stored: %d %v", len(list), err)
	}

	a := createApproval(t, s, approvalInput(s, "k-reason"))
	if _, err := s.DecideActionApproval(ctx, ActionDecisionInput{ID: a.ID, DecidedBy: "github:root", Decision: DecisionDeny,
		Reason: "rotating, old key was AKIA" + strings.Repeat("A", 16)}); !errors.Is(err, ErrSecretInText) {
		t.Fatalf("reason: err = %v, want ErrSecretInText", err)
	}
	if got, err := s.ActionApproval(ctx, a.ID); err != nil || got.State != ApprovalPending || got.Reason != "" {
		t.Fatalf("refused decision changed it: %+v %v", got, err)
	}
}

func TestDecideActionApproval(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	a := createApproval(t, s, approvalInput(s, "k-1"))

	// The requester can never decide its own request.
	if _, err := s.DecideActionApproval(ctx, ActionDecisionInput{ID: a.ID, DecidedBy: agentPrincipal, Decision: DecisionApprove}); !errors.Is(err, ErrApprovalSelfDecision) {
		t.Fatalf("self = %v", err)
	}
	if _, err := s.DecideActionApproval(ctx, ActionDecisionInput{ID: a.ID, DecidedBy: "github:root", Decision: "maybe"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad decision = %v", err)
	}
	d, err := s.DecideActionApproval(ctx, ActionDecisionInput{ID: a.ID, DecidedBy: "github:root", Decision: DecisionDeny, Reason: "not today"})
	if err != nil || d.State != ApprovalDenied || d.DecidedBy != "github:root" || d.DecidedAt == nil || d.Reason != "not today" {
		t.Fatalf("deny = %+v %v", d, err)
	}
	// Only from pending.
	if _, err := s.DecideActionApproval(ctx, ActionDecisionInput{ID: a.ID, DecidedBy: "github:root", Decision: DecisionApprove}); !errors.Is(err, ErrApprovalAlreadyDecided) {
		t.Fatalf("re-decide = %v", err)
	}
	if _, err := s.DecideActionApproval(ctx, ActionDecisionInput{ID: "aar_missing", DecidedBy: "github:root", Decision: DecisionApprove}); !errors.Is(err, ErrApprovalNotFound) {
		t.Fatalf("missing = %v", err)
	}
}

func TestActionApprovalExpiresLazily(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	pending := createApproval(t, s, approvalInput(s, "k-pending"))
	ok := approved(t, s, "k-approved")

	realNow := s.now
	s.now = func() time.Time { return realNow().Add(2 * time.Hour) }
	for _, id := range []string{pending.ID, ok.ID} {
		got, err := s.ActionApproval(ctx, id)
		if err != nil || got.State != ApprovalExpired {
			t.Fatalf("read %s = %+v %v", id, got, err)
		}
	}
	list, err := s.ActionApprovals(ctx, ActionApprovalFilter{State: ApprovalExpired, ExecutionID: storeTestExecution})
	if err != nil || len(list) != 2 {
		t.Fatalf("expired list = %d %v", len(list), err)
	}
	if list, _ := s.ActionApprovals(ctx, ActionApprovalFilter{State: ApprovalPending, ExecutionID: storeTestExecution}); len(list) != 0 {
		t.Fatalf("pending list = %v", list)
	}
	if _, err := s.DecideActionApproval(ctx, ActionDecisionInput{ID: pending.ID, DecidedBy: "github:root", Decision: DecisionApprove}); !errors.Is(err, ErrApprovalExpired) {
		t.Fatalf("decide expired = %v", err)
	}
	if _, err := s.ConsumeActionApproval(ctx, ok.ID, ok.IntentHash); !errors.Is(err, ErrApprovalExpired) {
		t.Fatalf("consume expired = %v", err)
	}
	// A retry of the stored request is still answered with it.
	in := approvalInput(s, "k-pending")
	in.ExpiresAt = pending.ExpiresAt
	if got, created, err := s.CreateActionApproval(ctx, in); err != nil || created || got.ID != pending.ID || got.State != ApprovalExpired {
		t.Fatalf("retry = %+v %v %v", got, created, err)
	}
}

func TestConsumeActionApprovalRefusals(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()

	pending := createApproval(t, s, approvalInput(s, "k-pending"))
	if _, err := s.ConsumeActionApproval(ctx, pending.ID, pending.IntentHash); !errors.Is(err, ErrApprovalNotApproved) {
		t.Fatalf("pending = %v", err)
	}
	denied := createApproval(t, s, approvalInput(s, "k-denied"))
	if _, err := s.DecideActionApproval(ctx, ActionDecisionInput{ID: denied.ID, DecidedBy: "github:root", Decision: DecisionDeny}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeActionApproval(ctx, denied.ID, denied.IntentHash); !errors.Is(err, ErrApprovalDenied) {
		t.Fatalf("denied = %v", err)
	}
	ok := approved(t, s, "k-ok")
	if _, err := s.ConsumeActionApproval(ctx, ok.ID, "sha256:"+strings.Repeat("0", 64)); !errors.Is(err, ErrApprovalIntentMismatch) {
		t.Fatalf("mismatch = %v", err)
	}
	c, err := s.ConsumeActionApproval(ctx, ok.ID, ok.IntentHash)
	if err != nil || c.State != ApprovalConsumed || c.ConsumedAt == nil {
		t.Fatalf("consume = %+v %v", c, err)
	}
	if _, err := s.ConsumeActionApproval(ctx, ok.ID, ok.IntentHash); !errors.Is(err, ErrApprovalConsumed) {
		t.Fatalf("second consume = %v", err)
	}
	// Consumed is terminal: it never reads as expired later.
	realNow := s.now
	s.now = func() time.Time { return realNow().Add(2 * time.Hour) }
	if got, _ := s.ActionApproval(ctx, ok.ID); got.State != ApprovalConsumed {
		t.Fatalf("consumed later reads %s", got.State)
	}
	if _, err := s.ConsumeActionApproval(ctx, "aar_missing", ok.IntentHash); !errors.Is(err, ErrApprovalNotFound) {
		t.Fatalf("missing = %v", err)
	}
}

func TestConsumeActionApprovalIsSingleUseUnderConcurrency(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	for round := 0; round < 5; round++ {
		a := approved(t, s, "k-race-"+string(rune('a'+round)))
		const racers = 8
		var wg sync.WaitGroup
		errs := make([]error, racers)
		start := make(chan struct{})
		for i := range racers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, errs[i] = s.ConsumeActionApproval(ctx, a.ID, a.IntentHash)
			}()
		}
		close(start)
		wg.Wait()
		won := 0
		for _, err := range errs {
			switch {
			case err == nil:
				won++
			case !errors.Is(err, ErrApprovalConsumed):
				t.Fatalf("loser = %v", err)
			}
		}
		if won != 1 {
			t.Fatalf("round %d: %d consumes succeeded, want exactly 1", round, won)
		}
	}
}
