package api

import (
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"html"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/argocd"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// The removal of a window is decided on the same page as an addition (same
// callback, cookie and flow), but what is shown and what is decided follow the
// approval's own kind. These tests pin the removal texts, the removal decide
// call, and that neither kind can be shown or decided as the other.

func (e *windowPageEnv) pendingRemoval() (string, workitems.ReleaseWindow) {
	e.t.Helper()
	b := make([]byte, 18)
	if _, err := crand.Read(b); err != nil {
		e.t.Fatal(err)
	}
	win := workitems.ReleaseWindow{Project: "apps", Applications: []string{"labs-portfolio"},
		Schedule: "0 3 * * 0", Duration: "1h", BaseSHA: "abab" + hex.EncodeToString(b)}
	intent, err := workitems.ReleaseWindowRemovalIntent(win)
	if err != nil {
		e.t.Fatal(err)
	}
	key, _ := workitems.ReleaseWindowRemovalIdempotencyKey(win)
	id, _ := win.ReleaseWindowRemovalID()
	pol := e.h.approvalPolicies()[workitems.ReleaseWindowRemovalPolicyRuleID]
	a, _, err := e.h.opts.WorkItems.CreateReleaseWindowRemovalApproval(context.Background(), win, workitems.ActionApprovalInput{
		ActionIntent: intent, RequestedBy: "principal:" + glovoOtherPRN, RequestedByPrincipalID: glovoOtherPRN,
		ActorKind: "agent", ActorName: "claude-code",
		IdempotencyKey: key, ExpiresAt: time.Now().Add(time.Hour), RiskLevel: "high",
		IntentSource: "release-window-removal:" + win.Project + "/" + id,
		SideEffect:   pol.SideEffect, PolicyDecision: pol.Decision, PolicyReasons: append([]string(nil), pol.Reasons...),
	})
	if err != nil {
		e.t.Fatalf("CreateReleaseWindowRemovalApproval: %v", err)
	}
	return a.ID, win
}

func TestReleaseWindowRemovalPage_DeciderApprovesWithEvidence(t *testing.T) {
	e := newWindowPageEnv(t)
	e.removalLink = true
	id, win := e.pendingRemoval()
	rec, ck, form := e.signIn(id, deciderClaims())
	body := html.UnescapeString(rec.Body.String())
	hash, _ := win.RemovalSHA256()
	for _, want := range []string{"Project: apps", "Applications (1): labs-portfolio",
		`Window to REMOVE: deny, cron "0 3 * * 0" (UTC), duration 1h`, "Removal hash: sha256:" + hash, win.BaseSHA,
		"removed from main and from Argo CD", "deletes it", "queued for merge", "no person reviews or merges it after you",
		"may sync during that time again", "nothing is changed in Git", "Approve removing this window"} {
		if !strings.Contains(body, want) {
			t.Fatalf("the decide page lacks %q:\n%s", want, body)
		}
	}
	// A removal reads as one: not the addition's wording.
	for _, not := range []string{"Window hash:", "goes into main", "Approve this window", "nothing is added to Git"} {
		if strings.Contains(body, not) {
			t.Fatalf("the removal page carries the addition's %q:\n%s", not, body)
		}
	}
	if rec.Code != http.StatusOK || form.Get("csrf") == "" {
		t.Fatalf("callback = %d", rec.Code)
	}
	if e.approval(id).State != workitems.ApprovalPending {
		t.Fatal("showing the removal decided it")
	}
	got := e.confirm(ck, form, "approve")
	if got.Code != http.StatusOK || !strings.Contains(got.Body.String(), "Release window removal approved") {
		t.Fatalf("confirm = %d %s", got.Code, got.Body.String())
	}
	if b := got.Body.String(); !strings.Contains(b, "no pull request exists yet") || !strings.Contains(b, "mctl_propose_window_removal") ||
		!strings.Contains(b, "deletes the window") || !strings.Contains(b, "queued for merge") || strings.Contains(b, "deployed") {
		t.Fatalf("approved page overclaims or misdescribes: %s", b)
	}
	a := e.approval(id)
	ev, err := workitems.ReleaseWindowRemovalDecisionOf(a)
	if a.State != workitems.ApprovalApproved || a.DecidedByPrincipalID != basketAdminPRN || err != nil || ev == nil ||
		a.AuthorityBasis != workitems.ReleaseWindowRemovalAuthorityBasis {
		t.Fatalf("decided row %+v, evidence %+v %v", a, ev, err)
	}
	if _, err := workitems.ReleaseWindowDecisionOf(a); err == nil {
		t.Fatal("the addition's decision reader accepted a removal")
	}
	if again := e.confirm(ck, form, "approve"); again.Code != http.StatusBadRequest {
		t.Fatalf("replayed confirm = %d", again.Code)
	}
}

func TestReleaseWindowRemovalPage_DeciderRejects(t *testing.T) {
	e := newWindowPageEnv(t)
	e.removalLink = true
	id, _ := e.pendingRemoval()
	_, ck, form := e.signIn(id, deciderClaims())
	got := e.confirm(ck, form, "reject")
	if got.Code != http.StatusOK || !strings.Contains(got.Body.String(), "Release window removal rejected") ||
		!strings.Contains(got.Body.String(), "the window stays") {
		t.Fatalf("reject = %d %s", got.Code, got.Body.String())
	}
	a := e.approval(id)
	if ev, err := workitems.ReleaseWindowRemovalDecisionOf(a); a.State != workitems.ApprovalDenied || ev == nil || err != nil {
		t.Fatalf("rejected row %+v %v %v", a, ev, err)
	}
}

// Lifting a window must not depend on the sync preview: an Application Argo CD
// no longer knows, or an Argo that cannot be read, does not stop it. (An
// addition is refused in both cases; the workflow checks a removal against main.)
func TestReleaseWindowRemovalPage_NeedsNoArgoPreview(t *testing.T) {
	for name, err := range map[string]error{"application gone": nil, "argo unreadable": argocd.ErrForbidden} {
		t.Run(name, func(t *testing.T) {
			e := newWindowPageEnv(t)
			e.removalLink = true
			e.argo.set("apps", "labs-portfolio", nil, err)
			id, _ := e.pendingRemoval()
			rec, ck, form := e.signIn(id, deciderClaims())
			if rec.Code != http.StatusOK || form.Get("csrf") == "" || strings.Contains(rec.Body.String(), "can sync now") {
				t.Fatalf("callback = %d %s", rec.Code, rec.Body.String())
			}
			if got := e.confirm(ck, form, "approve"); got.Code != http.StatusOK {
				t.Fatalf("confirm = %d %s", got.Code, got.Body.String())
			}
		})
	}
}

// What is shown after sign-in follows the approval, not the link that was
// opened: a removal opened through the addition's link still reads as a
// removal, and an addition through the removal's link as an addition, so a
// wrong link cannot make the decide screen say the other thing.
func TestReleaseWindowPage_TheDecideScreenFollowsTheApprovalNotTheLink(t *testing.T) {
	e := newWindowPageEnv(t)
	remID, _ := e.pendingRemoval()
	rec, ck, form := e.signIn(remID, deciderClaims()) // addition's link
	body := html.UnescapeString(rec.Body.String())
	if !strings.Contains(body, "Window to REMOVE:") || !strings.Contains(body, "removed from main and from Argo CD") ||
		strings.Contains(body, "Approve this window") {
		t.Fatalf("a removal behind the addition's link:\n%s", body)
	}
	if got := e.confirm(ck, form, "approve"); got.Code != http.StatusOK || !strings.Contains(got.Body.String(), "Release window removal approved") {
		t.Fatalf("confirm = %d %s", got.Code, got.Body.String())
	}
	if e.approval(remID).ActionKind != workitems.ActionKindReleaseWindowRemoval {
		t.Fatal("kind changed")
	}

	e2 := newWindowPageEnv(t)
	e2.removalLink = true
	addID, _ := e2.pendingWindow()
	rec, ck, form = e2.signIn(addID, deciderClaims()) // removal's link
	body = html.UnescapeString(rec.Body.String())
	if strings.Contains(body, "Window to REMOVE:") || !strings.Contains(body, "Window hash:") || !strings.Contains(body, "goes into main") {
		t.Fatalf("an addition behind the removal's link:\n%s", body)
	}
	got := e2.confirm(ck, form, "approve")
	a := e2.approval(addID)
	if got.Code != http.StatusOK || !strings.Contains(got.Body.String(), "Release window approved") ||
		a.AuthorityBasis != workitems.ReleaseWindowAuthorityBasis {
		t.Fatalf("confirm = %d %s; basis %s", got.Code, got.Body.String(), a.AuthorityBasis)
	}
}

func TestReleaseWindowRemovalPage_DecideURLAndRoute(t *testing.T) {
	e := newWindowPageEnv(t)
	id, _ := e.pendingRemoval()
	if got, want := e.h.releaseWindowApproval.removalDecideURL(id), "https://api.example"+releaseWindowRemovalPagePrefix+id; got != want {
		t.Fatalf("removalDecideURL = %s, want %s", got, want)
	}
	if got := e.h.releaseWindowApproval.decideURL(id); strings.Contains(got, "removal") {
		t.Fatalf("the addition's decideURL points at the removal page: %s", got)
	}
	// A malformed reference is refused without reading anything.
	if got := e.send(http.MethodGet, releaseWindowRemovalPagePrefix+"not-a-ref", nil, nil); got.Code != http.StatusBadRequest {
		t.Fatalf("malformed ref = %d", got.Code)
	}
}

// A removal row is not a grant and not decidable at the grant page, as an
// addition is not.
func TestReleaseWindowRemovalPage_IsIsolatedFromTheGrantPage(t *testing.T) {
	e := newWindowPageEnv(t)
	remID, win := e.pendingRemoval()
	hash, _ := win.RemovalSHA256()
	rec, _, form := e.releasePageEnv.signIn(remID, deciderClaims())
	if rec.Code != http.StatusNotFound || form.Get("csrf") != "" || strings.Contains(rec.Body.String(), hash) {
		t.Fatalf("removal row at the grant page: %d %s", rec.Code, rec.Body.String())
	}
	if e.approval(remID).State != workitems.ApprovalPending {
		t.Fatal("a grant-page sign-in decided a removal")
	}
}
