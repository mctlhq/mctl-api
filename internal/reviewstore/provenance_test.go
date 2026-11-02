package reviewstore

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/mctlhq/mctl-api/internal/executionprovenance"
	"github.com/mctlhq/mctl-api/internal/reviewreceipts"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

type fakeProvenance struct {
	recs     map[string]*workitems.Provenance
	attempts map[string]map[string]bool // lineage -> attempt ids
	readErr  error
}

func (f *fakeProvenance) ExecutionProvenance(_ context.Context, id string) (*workitems.Provenance, error) {
	if f.readErr != nil {
		return nil, f.readErr
	}
	if p, ok := f.recs[id]; ok {
		return p, nil
	}
	return nil, fmt.Errorf("%w: %s", workitems.ErrProvenanceAbsent, id)
}

func (f *fakeProvenance) LineageAttempts(_ context.Context, root string, ids []string) (map[string]bool, error) {
	if f.readErr != nil {
		return nil, f.readErr
	}
	out := map[string]bool{}
	for _, id := range ids {
		if f.attempts[root][id] {
			out[id] = true
		}
	}
	return out, nil
}

const authorExec = "we_11111111-2222-3333-4444-555555555555"

func provFixture() (*fakeProvenance, string, string) { return provFixtureFor(authorExec) }

func provFixtureFor(exec string) (*fakeProvenance, string, string) {
	authorExec := exec
	at := executionprovenance.AttemptID("argo", "wf-author")
	ln := executionprovenance.LineageRoot(authorExec)
	other := executionprovenance.AttemptID("argo", "wf-earlier")
	return &fakeProvenance{
		recs:     map[string]*workitems.Provenance{authorExec: {ExecutionID: authorExec, AttemptID: at, LineageRoot: ln}},
		attempts: map[string]map[string]bool{ln: {at: true, other: true}},
	}, at, ln
}

func TestCheckAuthoring(t *testing.T) {
	fp, at, ln := provFixture()
	foreign := executionprovenance.AttemptID("argo", "wf-foreign")
	earlier := executionprovenance.AttemptID("argo", "wf-earlier")
	mk := func(mode, exec, root string, attempts ...string) reviewreceipts.ReviewRequest {
		return reviewreceipts.ReviewRequest{Mode: mode, AuthoringExecutionID: exec, AuthoringLineageRoot: root, AuthoringAttemptIDs: attempts}
	}
	s := &Store{provenance: fp}
	for _, c := range []struct {
		name string
		s    *Store
		req  reviewreceipts.ReviewRequest
		want error
	}{
		{"worker proven", s, mk("worker", authorExec, ln, at), nil},
		{"worker with earlier attempt of the lineage", s, mk("worker", authorExec, ln, at, earlier), nil},
		{"worker ex- id", s, mk("worker", "ex-0123456789abcdef", ln, at), ErrAuthoringUnproven},
		{"worker absent record", s, mk("worker", "we_unknown", ln, at), ErrAuthoringUnproven},
		{"worker lineage mismatch", s, mk("worker", authorExec, "ln_"+"0123456789abcdef0123456789abcdef", at), ErrAuthoringUnproven},
		{"worker own attempt missing", s, mk("worker", authorExec, ln, earlier), ErrAuthoringUnproven},
		{"worker foreign attempt", s, mk("worker", authorExec, ln, at, foreign), ErrAuthoringUnproven},
		{"worker empty facts", s, mk("worker", authorExec, ""), ErrAuthoringUnproven},
		{"manual empty facts", s, mk("manual", "ex-0123456789abcdef", ""), nil},
		{"manual wrong facts", s, mk("manual", authorExec, ln, foreign), ErrAuthoringUnproven},
		{"manual right facts", s, mk("manual", authorExec, ln, at), nil},
		{"lookup error", &Store{provenance: &fakeProvenance{readErr: errors.New("db down")}}, mk("worker", authorExec, ln, at), ErrProvenanceUnavailable},
		{"lookup not wired", &Store{}, mk("worker", authorExec, ln, at), ErrProvenanceUnavailable},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := c.s.checkAuthoring(context.Background(), c.req)
			if c.want == nil && err != nil || c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			if c.want == ErrProvenanceUnavailable && errors.Is(err, workitems.ErrProvenanceAbsent) {
				t.Fatal("unavailable collapsed into absent")
			}
		})
	}
}

func TestProveReviewer(t *testing.T) {
	fp, at, ln := provFixture()
	s := &Store{provenance: fp}
	gotAt, gotLn, err := s.ProveReviewer(context.Background(), authorExec)
	if err != nil || gotAt != at || gotLn != ln {
		t.Fatalf("got %s %s %v", gotAt, gotLn, err)
	}
	if _, _, err := s.ProveReviewer(context.Background(), "we_unknown"); !errors.Is(err, ErrExecutionUnproven) {
		t.Fatalf("absent: %v", err)
	}
	s = &Store{provenance: &fakeProvenance{readErr: errors.New("db down")}}
	if _, _, err := s.ProveReviewer(context.Background(), authorExec); !errors.Is(err, ErrProvenanceUnavailable) {
		t.Fatalf("read error: %v", err)
	}
}
