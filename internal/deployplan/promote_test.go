package deployplan

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

const (
	promDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	promDep    = "dep_11111111-1111-1111-1111-111111111111"
)

func previewRecord() *Record {
	return &Record{ID: promDep, Tenant: "admins", Service: "api", Environment: EnvironmentPreview,
		Revision: testRev, Status: RecordSubmitted, RunResult: RunSucceeded, Health: HealthHealthy, ImageDigest: promDigest}
}

func TestPromoteIntent_CanonicalRoundTrip(t *testing.T) {
	in := NewPromoteIntent(previewRecord())
	c, err := in.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParsePromoteIntent(c)
	if err != nil || got != in {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	if got.ImageTag != "rev-"+testRev || got.ImageDigest != promDigest {
		t.Fatalf("tag/digest: %+v", got)
	}
}

func TestPromoteIntent_ParseRefuses(t *testing.T) {
	good, _ := NewPromoteIntent(previewRecord()).Canonical()
	for name, c := range map[string]string{
		"unknown field":    strings.Replace(good, `"kind"`, `"extra":1,"kind"`, 1),
		"spaces":           strings.Replace(good, `","`, `", "`, 1),
		"trailing":         good + "{}",
		"bad digest":       strings.Replace(good, "sha256:aaaa", "sha256:zzzz", 1),
		"other kind":       strings.Replace(good, PromoteIntentKind, "x", 1),
		"bad dep id":       strings.Replace(good, "dep_1111", "dep_xxxx", 1),
		"tag with a slash": strings.Replace(good, `"rev-`, `"a/rev-`, 1),
		"empty":            "",
	} {
		if _, err := ParsePromoteIntent(c); !errors.Is(err, ErrPromoteIntent) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestPromoteSourceUnusable(t *testing.T) {
	if why := PromoteSourceUnusable(previewRecord()); why != "" {
		t.Fatalf("a verified preview is usable, got %q", why)
	}
	for name, mutate := range map[string]func(*Record){
		"production record": func(r *Record) { r.Environment = EnvironmentProduction },
		"not submitted":     func(r *Record) { r.Status = RecordSubmitting },
		"run failed":        func(r *Record) { r.RunResult = RunFailed },
		"run unknown":       func(r *Record) { r.RunResult = "" },
		"unhealthy":         func(r *Record) { r.Health = HealthUnhealthy },
		"health unknown":    func(r *Record) { r.Health = HealthUnknown },
		"no digest":         func(r *Record) { r.ImageDigest = "" },
		"bad revision":      func(r *Record) { r.Revision = "main" },
	} {
		r := previewRecord()
		mutate(r)
		if PromoteSourceUnusable(r) == "" {
			t.Errorf("%s: a record that is not a verified preview was usable", name)
		}
	}
}

func TestCompilePromote_ChangesOnlyTagAndDigest(t *testing.T) {
	base := "image:\n  repository: ghcr.io/mctlhq/api\n  tag: 1.0.0\n  digest: sha256:" + strings.Repeat("b", 64) + "\nreplicas: 2\n"
	before, after, err := CompilePromote([]byte(base), NewPromoteIntent(previewRecord()))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := RenderYAML(before)
	a, _ := RenderYAML(after)
	d := UnifiedDiff(b, a)
	if !strings.Contains(d, "rev-"+testRev) || !strings.Contains(d, promDigest) {
		t.Fatalf("diff misses the promotion:\n%s", d)
	}
	for _, line := range strings.Split(d, "\n") {
		changed := (strings.HasPrefix(line, "+") || strings.HasPrefix(line, "-")) && !strings.HasPrefix(line, "+++") && !strings.HasPrefix(line, "---")
		if changed && !strings.Contains(line, "tag:") && !strings.Contains(line, "digest:") {
			t.Fatalf("diff changes more than tag and digest: %q\n%s", line, d)
		}
	}
	if before["image"].(map[string]any)["tag"] != "1.0.0" {
		t.Fatal("the before map was modified")
	}
}

func TestCompilePromote_RefusesValuesThatCannotTakeIt(t *testing.T) {
	for name, base := range map[string]string{
		"no image":      "replicas: 1\n",
		"no repository": "image:\n  tag: x\n",
		"image a list":  "image:\n  - a\n",
		"not a mapping": "- a\n",
	} {
		if _, _, err := CompilePromote([]byte(base), NewPromoteIntent(previewRecord())); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRequiredApproval_Promote(t *testing.T) {
	a := RequiredApproval(EnvironmentProduction, ActionPromote)
	if !a.Required || a.Role != "owner" || a.Reason != "promote_requires_approval" {
		t.Fatalf("%+v", a)
	}
	if RequiredApproval(EnvironmentProduction, ActionUpdate).Reason == "promote_requires_approval" {
		t.Fatal("only a promote gets the promote reason")
	}
}

func TestProductionHost(t *testing.T) {
	for want, v := range map[string]map[string]any{
		"a.example.com": {"ingress": map[string]any{"host": "a.example.com"}},
		"b.example.com": {"ingress": map[string]any{"hosts": []any{"b.example.com"}}},
		"c.example.com": {"ingress": map[string]any{"hosts": []any{map[string]any{"host": "c.example.com"}}}},
		"":              {},
	} {
		if got := ProductionHost(v); got != want {
			t.Errorf("%v: %q want %q", v, got, want)
		}
	}
}

func TestStore_ProductionIsOnlyForPromote(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	p := testPlan("c")
	p.Environment = EnvironmentProduction
	if _, _, err := s.Insert(ctx, p); err == nil {
		t.Fatal("a production plan with action update was stored")
	}
	p = testPlan("d")
	p.Action = ActionPromote
	if _, _, err := s.Insert(ctx, p); err == nil {
		t.Fatal("a preview plan with action promote was stored")
	}
	p = testPlan("e")
	p.Environment, p.Action = EnvironmentProduction, ActionPromote
	if _, _, err := s.Insert(ctx, p); err != nil {
		t.Fatalf("a production promote plan: %v", err)
	}
}

// The comparison is stored once with the run result, only for a promotion,
// and the store's trigger holds both rules.
func TestStore_DigestCheckOnPromotionRecords(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	mk := func(seed string, promo bool) *Record {
		p := testPlan(seed)
		if promo {
			p.Environment, p.Action = EnvironmentProduction, ActionPromote
		}
		stored, _, err := s.Insert(ctx, p)
		if err != nil {
			t.Fatal(err)
		}
		r := NewRecord(stored, "aar_"+seed, "principal:2", "principal:1", "wf-"+seed, time.Now())
		if promo {
			r.SourceDeploymentID = promDep
		}
		r, err = s.InsertRecord(ctx, r)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.SetRecordSubmission(ctx, r.ID, RecordSubmitted, "wf-"+seed); err != nil {
			t.Fatal(err)
		}
		return r
	}
	promo := mk("a", true)
	got, err := s.SetRunResult(ctx, promo.ID, RunOutcome{Result: RunSucceeded, ImageDigest: promDigest, DigestCheck: DigestMatch})
	if err != nil || got.DigestCheck != DigestMatch || got.SourceDeploymentID != promDep {
		t.Fatalf("promotion: %+v %v", got, err)
	}
	// A record that is not a promotion cannot carry a check.
	plain := mk("b", false)
	if _, err := s.SetRunResult(ctx, plain.ID, RunOutcome{Result: RunSucceeded, DigestCheck: DigestMatch}); err == nil {
		t.Fatal("a non-promotion stored a digest check")
	}
	if _, err := s.SetRunResult(ctx, plain.ID, RunOutcome{Result: RunSucceeded, DigestCheck: "bogus"}); err == nil {
		t.Fatal("an unknown check was stored")
	}
}
