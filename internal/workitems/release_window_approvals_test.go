package workitems

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

const rwBase = "0123456789abcdef0123456789abcdef01234567"

func rwWindow() ReleaseWindow {
	return ReleaseWindow{Project: "apps", Applications: []string{"labs-mctl-telegram", "labs-mctl-web"},
		Schedule: "0 22 * * 5", Duration: "48h", BaseSHA: rwBase}
}

// The hashes below were produced by mctl-gitops scripts/release-window-insert.py
// (`hash PROJECT` over the window object scripts/render-sync-window.py emits),
// not by this package. The workflow refuses unless its hash equals the approved
// one, so a Go encoding that drifts from the Python one would make every
// approved window unappliable; this is the test that notices.
func TestWindowSHA256MatchesTheWorkflowScript(t *testing.T) {
	for _, c := range []struct {
		name string
		w    ReleaseWindow
		want string
	}{
		{"apps", rwWindow(), "1e5d4541491c0be92464c638102358a91e539103805dbd0c753474b9c43e7cad"},
		{"platform", ReleaseWindow{Project: "platform", Applications: []string{"admins-mctl-api"},
			Schedule: "30 1 * * 1-5", Duration: "1h30m", BaseSHA: rwBase},
			"decf5a6798011a1e50b42f73e16a5f78bca3462f457ceae8515eb4ce48050631"},
	} {
		got, err := c.w.WindowSHA256()
		if err != nil || got != c.want {
			t.Errorf("%s: WindowSHA256 = %q, %v; the workflow script gives %s", c.name, got, err, c.want)
		}
	}
}

func TestWindowHashBindsTheProject(t *testing.T) {
	a, b := rwWindow(), rwWindow()
	b.Project = "platform"
	ha, _ := a.WindowSHA256()
	hb, _ := b.WindowSHA256()
	ia, _ := a.ReleaseWindowID()
	ib, _ := b.ReleaseWindowID()
	if ha == hb || ia == ib {
		t.Fatalf("an approval for one project must not hash or name the same as another: %s %s", ia, ib)
	}
}

func TestReleaseWindowValidateRefuses(t *testing.T) {
	bad := map[string]func(*ReleaseWindow){
		"default project":      func(w *ReleaseWindow) { w.Project = "default" },
		"empty project":        func(w *ReleaseWindow) { w.Project = "" },
		"no applications":      func(w *ReleaseWindow) { w.Applications = nil },
		"glob application":     func(w *ReleaseWindow) { w.Applications = []string{"labs-*"} },
		"upper application":    func(w *ReleaseWindow) { w.Applications = []string{"Labs-web"} },
		"unsorted":             func(w *ReleaseWindow) { w.Applications = []string{"b", "a"} },
		"duplicate":            func(w *ReleaseWindow) { w.Applications = []string{"a", "a"} },
		"comma in name":        func(w *ReleaseWindow) { w.Applications = []string{"a,b"} },
		"newline in schedule":  func(w *ReleaseWindow) { w.Schedule = "0 22 * * 5\n" },
		"four-field cron":      func(w *ReleaseWindow) { w.Schedule = "0 22 * *" },
		"named weekday":        func(w *ReleaseWindow) { w.Schedule = "0 22 * * FRI" },
		"bad duration":         func(w *ReleaseWindow) { w.Duration = "2d" },
		"zero hours":           func(w *ReleaseWindow) { w.Duration = "0h" },
		"zero minutes":         func(w *ReleaseWindow) { w.Duration = "0m" },
		"minutes before hours": func(w *ReleaseWindow) { w.Duration = "30m1h" },
		"hours twice":          func(w *ReleaseWindow) { w.Duration = "1h1h" },
		"leading zero":         func(w *ReleaseWindow) { w.Duration = "01h" },
		"five digit duration":  func(w *ReleaseWindow) { w.Duration = "10000h" },
		"oversized schedule": func(w *ReleaseWindow) {
			w.Schedule = strings.Repeat("0,", 60) + "0 22 * * 5"
		},
		"empty duration": func(w *ReleaseWindow) { w.Duration = "" },
		"short base":     func(w *ReleaseWindow) { w.BaseSHA = "abc" },
		"upper base":     func(w *ReleaseWindow) { w.BaseSHA = strings.ToUpper(rwBase) },
		"too many apps": func(w *ReleaseWindow) {
			w.Applications = nil
			for i := 0; i <= MaxReleaseWindowApplications; i++ {
				w.Applications = append(w.Applications, fmt.Sprintf("app-%02d", i))
			}
		},
	}
	for name, mutate := range bad {
		w := rwWindow()
		mutate(&w)
		if err := w.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: Validate = %v, want ErrInvalid", name, err)
		}
	}
	if err := rwWindow().Validate(); err != nil {
		t.Fatalf("the good window is refused: %v", err)
	}
}

// The widest legal window must still fit the target column, or a request the
// workflow would accept could never be stored.
func TestWidestWindowFitsTheTarget(t *testing.T) {
	w := rwWindow()
	w.Applications = nil
	for i := 0; i < MaxReleaseWindowApplications; i++ {
		w.Applications = append(w.Applications, fmt.Sprintf("%02d-%s", i, strings.Repeat("a", 60)))
	}
	// The longest schedule Validate lets through, so this really is the widest legal window.
	w.Schedule = strings.Repeat("0,", 45) + "0 22 * * 5"
	if len(w.Schedule) > MaxReleaseWindowScheduleLen {
		t.Fatalf("test schedule is %d bytes, over the %d bound", len(w.Schedule), MaxReleaseWindowScheduleLen)
	}
	target, err := ReleaseWindowTarget(w)
	if err != nil {
		t.Fatal(err)
	}
	if len(target) > MaxApprovalTargetBytes {
		t.Fatalf("widest target is %d bytes, over the %d limit", len(target), MaxApprovalTargetBytes)
	}
}

func rwRow(t *testing.T, w ReleaseWindow) *ActionApprovalRequest {
	t.Helper()
	in, err := ReleaseWindowIntent(w)
	if err != nil {
		t.Fatal(err)
	}
	return &ActionApprovalRequest{ID: "aar_x", ExecutionID: in.ExecutionID, ActionKind: in.ActionKind,
		Target: in.Target, ArgsDigest: in.ArgsDigest, ArtifactHash: in.ArtifactHash}
}

func TestReleaseWindowOfRoundTripsAndRejectsTampering(t *testing.T) {
	w := rwWindow()
	got, err := ReleaseWindowOf(rwRow(t, w))
	if err != nil || fmt.Sprint(got) != fmt.Sprint(w) {
		t.Fatalf("round trip: %v %v, want %v", got, err, w)
	}
	other := rwWindow()
	other.Applications = []string{"labs-mctl-telegram"}
	otherIn, _ := ReleaseWindowIntent(other)

	tamper := map[string]func(*ActionApprovalRequest){
		"other kind":         func(a *ActionApprovalRequest) { a.ActionKind = ActionKindReleaseGrant },
		"window swapped":     func(a *ActionApprovalRequest) { a.Target = otherIn.Target },
		"digest swapped":     func(a *ActionApprovalRequest) { a.ArgsDigest = otherIn.ArgsDigest },
		"hash swapped":       func(a *ActionApprovalRequest) { a.ArtifactHash = otherIn.ArtifactHash },
		"base moved":         func(a *ActionApprovalRequest) { a.ExecutionID = strings.Repeat("f", 40) },
		"project in head":    func(a *ActionApprovalRequest) { a.Target = strings.Replace(a.Target, "apps/", "platform/", 1) },
		"unknown json field": func(a *ActionApprovalRequest) { a.Target = strings.Replace(a.Target, `"kind"`, `"x":1,"kind"`, 1) },
		"allow kind":         func(a *ActionApprovalRequest) { a.Target = strings.Replace(a.Target, `"deny"`, `"allow"`, 1) },
		"no window":          func(a *ActionApprovalRequest) { a.Target = "apps/w-000000000000" },
	}
	for name, mutate := range tamper {
		a := rwRow(t, w)
		mutate(a)
		if _, err := ReleaseWindowOf(a); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: ReleaseWindowOf = %v, want ErrInvalid", name, err)
		}
	}
	if _, err := ReleaseWindowOf(nil); !errors.Is(err, ErrInvalid) {
		t.Errorf("nil row: %v", err)
	}
}

func rwInput(s *Store, w ReleaseWindow, requester string) ActionApprovalInput {
	in, _ := ReleaseWindowIntent(w)
	key, _ := ReleaseWindowIdempotencyKey(w)
	id, _ := w.ReleaseWindowID()
	return ActionApprovalInput{
		ActionIntent: in, RequestedBy: requester, RequestedByPrincipalID: "prn_requester",
		IdempotencyKey: key, ExpiresAt: s.now().Add(time.Hour),
		RiskLevel: "high", IntentSource: "release-window:" + w.Project + "/" + id,
		SideEffect: "write", PolicyDecision: "require_approval", PolicyReasons: []string{ReleaseWindowPolicyRuleID},
	}
}

func TestCreateReleaseWindowApprovalBindsTheWindow(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	w := rwWindow()

	bad := func(name string, mutate func(*ReleaseWindow, *ActionApprovalInput)) {
		t.Helper()
		ww, in := w, rwInput(s, w, "oidc:a")
		mutate(&ww, &in)
		if _, _, err := s.CreateReleaseWindowApproval(ctx, ww, in); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
	bad("intent of another window", func(_ *ReleaseWindow, in *ActionApprovalInput) {
		o := rwWindow()
		o.Duration = "24h"
		in.ActionIntent, _ = ReleaseWindowIntent(o)
	})
	bad("other target", func(_ *ReleaseWindow, in *ActionApprovalInput) { in.Target = "apps/w-000000000000#{}" })
	bad("other policy", func(_ *ReleaseWindow, in *ActionApprovalInput) { in.PolicyRuleID = ReleaseGrantPolicyRuleID })
	bad("idempotency key not derived", func(_ *ReleaseWindow, in *ActionApprovalInput) { in.IdempotencyKey = "x" })
	bad("default project", func(ww *ReleaseWindow, in *ActionApprovalInput) { ww.Project = "default" })

	first, created, err := s.CreateReleaseWindowApproval(ctx, w, rwInput(s, w, "oidc:a"))
	if err != nil || !created {
		t.Fatalf("create: %v %v", created, err)
	}
	if got, err := ReleaseWindowOf(first); err != nil || got.Project != "apps" {
		t.Fatalf("the stored row is not a readable window: %v %v", got, err)
	}
	again, created, err := s.CreateReleaseWindowApproval(ctx, w, rwInput(s, w, "oidc:a"))
	if err != nil || created || again.ID != first.ID {
		t.Fatalf("replay: %v %v %v, want the stored row", again, created, err)
	}
	// The same window on a later main is another request: its approval is
	// the one the workflow would otherwise refuse as stale.
	later := w
	later.BaseSHA = strings.Repeat("e", 40)
	other, created, err := s.CreateReleaseWindowApproval(ctx, later, rwInput(s, later, "oidc:a"))
	if err != nil || !created || other.ID == first.ID {
		t.Fatalf("a later base must be a new request: %v %v", created, err)
	}

	id, _ := w.ReleaseWindowID()
	rows, err := s.ReleaseWindowApprovals(ctx, "apps", id, 0)
	if err != nil || len(rows) != 2 {
		t.Fatalf("listing %s: %d rows, %v, want 2", id, len(rows), err)
	}
	if _, err := s.ReleaseWindowApprovals(ctx, "default", id, 0); !errors.Is(err, ErrInvalid) {
		t.Errorf("listing the default project: %v, want ErrInvalid", err)
	}
	if _, err := s.ReleaseWindowApprovals(ctx, "apps", "w-%", 0); !errors.Is(err, ErrInvalid) {
		t.Errorf("listing a LIKE pattern: %v, want ErrInvalid", err)
	}
}

// A window request is not a release grant and the other way round: neither
// the generic paths nor the grant's own decide path may move it.
func TestReleaseWindowIsNotSpendableByAnyOtherPath(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	w := rwWindow()

	in := rwInput(s, w, "oidc:a")
	if _, _, err := s.CreateActionApproval(ctx, in); !errors.Is(err, ErrApprovalKindNotCreatable) {
		t.Errorf("generic create of %s: %v, want ErrApprovalKindNotCreatable", ActionKindReleaseWindow, err)
	}
	a, _, err := s.CreateReleaseWindowApproval(ctx, w, in)
	if err != nil {
		t.Fatal(err)
	}
	calls := map[string]error{}
	_, calls["decide"] = s.DecideActionApproval(ctx, ActionDecisionInput{ID: a.ID, DecidedBy: "oidc:other",
		DecidedByPrincipalID: "prn_other", Decision: DecisionApprove})
	_, calls["decide-deploy"] = s.DecideDeployApproval(ctx, ActionDecisionInput{ID: a.ID, DecidedBy: "oidc:other",
		DecidedByPrincipalID: "prn_other", Decision: DecisionApprove})
	_, calls["decide-release-grant"] = s.DecideReleaseApproval(ctx, ReleaseDecisionInput{ID: a.ID, DecidedBy: "oidc:other",
		DecidedByPrincipalID: "prn_other", Approve: true})
	_, calls["consume"] = s.ConsumeActionApproval(ctx, a.ID, a.IntentHash)
	_, calls["mark"] = s.MarkActionApprovalExecuted(ctx, a.ID, a.Target, a.ArtifactHash, a.RequestedBy)
	_, calls["reserve"] = s.ReserveActionApproval(ctx, a.ID, a.Target, a.ArtifactHash, a.RequestedBy, time.Hour)
	for name, err := range calls {
		if err == nil {
			t.Errorf("%s on a pending release.window row succeeded", name)
		}
	}
	cur, err := s.ActionApproval(ctx, a.ID)
	if err != nil || cur.State != ApprovalPending {
		t.Errorf("another path moved the row: %v %v, want pending", cur, err)
	}
}
