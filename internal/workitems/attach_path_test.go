package workitems

// T15 (mctl-api#917): every way an execution is inserted records its
// server-derived attach_path and whether the service principal acted
// directly; the review eligibility rule reads nothing else.

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func directService() Mutation {
	m := as(platform)
	m.ActorDirectService = true
	return m
}

func provOf(t *testing.T, s *Store, id string) *Provenance {
	t.Helper()
	p, err := s.ExecutionProvenance(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func wantAttach(t *testing.T, s *Store, what, id, path string, direct bool) {
	t.Helper()
	p := provOf(t, s, id)
	if p.AttachPath != path || p.AttachedDirectService != direct {
		t.Errorf("%s: attach_path=%q attached_direct_service=%v, want %q %v", what, p.AttachPath, p.AttachedDirectService, path, direct)
	}
}

func TestProvenanceRecordsAttachPathAndDirectService(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()

	// attach, by the platform directly and by anyone else.
	w := open(t, s, CreateInput{})
	direct, _, err := s.AttachExecution(ctx, ExecutionInput{Mutation: directService(), WorkItemID: w.ID, Engine: EngineTemporal, EngineRef: "ap-1", Phase: PhaseSucceeded})
	if err != nil {
		t.Fatal(err)
	}
	wantAttach(t, s, "direct-service attach", direct.ID, AttachPathAttach, true)
	w2 := open(t, s, CreateInput{})
	dev, _, err := s.AttachExecution(ctx, ExecutionInput{Mutation: as("github:alice"), WorkItemID: w2.ID, Engine: EngineTemporal, EngineRef: "ap-2", Phase: PhaseSucceeded})
	if err != nil {
		t.Fatal(err)
	}
	wantAttach(t, s, "developer attach", dev.ID, AttachPathAttach, false)

	// resume, by a developer and by the platform directly.
	cur, _ := s.Get(ctx, w2.ID)
	_, devResumed, _, err := s.Resume(ctx, ResumeInput{Mutation: keyed("github:alice", "ap-r1", "h"), WorkItemID: w2.ID,
		ExpectedStateVersion: cur.StateVersion, Engine: EngineTemporal, EngineRef: "ap-3"})
	if err != nil {
		t.Fatal(err)
	}
	wantAttach(t, s, "developer resume", devResumed.ID, AttachPathResume, false)
	cur, _ = s.Get(ctx, w.ID)
	svcResume := directService()
	svcResume.IdempotencyKey, svcResume.RequestHash = "ap-r2", "h"
	_, svcResumed, _, err := s.Resume(ctx, ResumeInput{Mutation: svcResume, WorkItemID: w.ID,
		ExpectedStateVersion: cur.StateVersion, Engine: EngineTemporal, EngineRef: "ap-4"})
	if err != nil {
		t.Fatal(err)
	}
	wantAttach(t, s, "direct-service resume", svcResumed.ID, AttachPathResume, true)

	// fulfil_start and fulfil_resume, through the execution-request flow.
	w3 := open(t, s, CreateInput{})
	requestExecution(t, s, xrInput(w3, ExecutionRequestStart, Mutation{}))
	x := claim(t, s)
	in := fulfil(x, x.ClaimToken, "ap-5")
	in.Mutation = directService()
	_, _, started, _, err := s.FulfilExecutionRequest(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	wantAttach(t, s, "fulfil start", started.ID, AttachPathFulfilStart, true)
	if _, _, err := s.AttachExecution(ctx, ExecutionInput{Mutation: as(platform), WorkItemID: w3.ID, Engine: EngineTemporal, EngineRef: "ap-5", Phase: PhaseSucceeded}); err != nil {
		t.Fatal(err)
	}
	parked, err := s.Transition(ctx, TransitionInput{Mutation: as("github:alice"), WorkItemID: w3.ID, Action: ActionWait, WaitingReason: WaitingInput, ExpectedStateVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	resume := xrInput(parked, ExecutionRequestResume, Mutation{})
	resume.ResumedFromExecutionID = started.ID
	requestExecution(t, s, resume)
	y := claim(t, s)
	// Not marked direct: fulfilment records the mutation's fact, it does
	// not assume it.
	_, _, resumed, _, err := s.FulfilExecutionRequest(ctx, fulfil(y, y.ClaimToken, "ap-6"))
	if err != nil {
		t.Fatal(err)
	}
	wantAttach(t, s, "fulfil resume (not direct)", resumed.ID, AttachPathFulfilResume, false)
}

// The new columns are as immutable as the rest of the row.
func TestProvenanceAttachColumnsAreImmutable(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	w := open(t, s, CreateInput{})
	e, _, err := s.AttachExecution(ctx, ExecutionInput{Mutation: as("github:alice"), WorkItemID: w.ID, Engine: EngineTemporal, EngineRef: "imm-917", Phase: PhaseRunning})
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`UPDATE execution_provenance SET attached_direct_service = true WHERE execution_id=$1`,
		`UPDATE execution_provenance SET attach_path = 'fulfil_start' WHERE execution_id=$1`,
	} {
		if _, err := s.pool.Exec(ctx, q, e.ID); err == nil || !strings.Contains(err.Error(), "immutable") {
			t.Fatalf("%s: err=%v, want an 'immutable' refusal", q, err)
		}
	}
	wantAttach(t, s, "after refused updates", e.ID, AttachPathAttach, false)
}

// insertProvenance refuses an empty path before touching the transaction.
func TestInsertProvenanceRequiresAPath(t *testing.T) {
	err := insertProvenance(context.Background(), nil, &Execution{ID: ExecutionIDPrefix + "x"}, "", directService(), "", time.Now())
	if err == nil || !strings.Contains(err.Error(), "attach path is required") {
		t.Fatalf("empty attach path: %v, want a refusal", err)
	}
}

// Guard: every call of insertExecution / insertProvenance (and of the two tx
// helpers that thread the path) is known, and passes either one of the
// AttachPath constants or the enclosing function's own attachPath
// parameter. A new caller, or an empty / literal path, fails here and must
// be reviewed for whether its attacher may ever be reviewer-eligible.
func TestEveryExecutionInsertPassesAnAttachPath(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	// callee -> index of its attachPath argument.
	pathArg := map[string]int{"insertExecution": 9, "insertProvenance": 5, "attachNewTx": 4, "resumeTx": 4}
	allowed := map[string]bool{"AttachPathAttach": true, "AttachPathResume": true, "AttachPathFulfilStart": true, "AttachPathFulfilResume": true}
	var callers []string
	fset := token.NewFileSet()
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				id, ok := call.Fun.(*ast.Ident)
				if !ok {
					return true
				}
				idx, tracked := pathArg[id.Name]
				if !tracked {
					return true
				}
				callers = append(callers, fn.Name.Name+"->"+id.Name)
				if len(call.Args) <= idx {
					t.Errorf("%s: %s call has %d args", fset.Position(call.Pos()), id.Name, len(call.Args))
					return true
				}
				switch a := call.Args[idx].(type) {
				case *ast.Ident:
					if !allowed[a.Name] && a.Name != "attachPath" {
						t.Errorf("%s: %s passes attach path %s, want an AttachPath constant", fset.Position(call.Pos()), id.Name, a.Name)
					}
				default:
					t.Errorf("%s: %s passes a non-identifier attach path (a literal?)", fset.Position(call.Pos()), id.Name)
				}
				return true
			})
		}
	}
	sort.Strings(callers)
	want := []string{
		"AttachExecution->attachNewTx",
		"FulfilExecutionRequest->attachNewTx",
		"FulfilExecutionRequest->resumeTx",
		"Resume->resumeTx",
		"attachNewTx->insertExecution",
		"insertExecution->insertProvenance",
		"resumeTx->insertExecution",
	}
	if strings.Join(callers, ",") != strings.Join(want, ",") {
		t.Fatalf("execution insert call sites = %v\nwant %v\n(a new caller must pass an explicit attach path and be added here)", callers, want)
	}
}
