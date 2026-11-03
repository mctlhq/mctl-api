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

package reviewstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/mctlhq/mctl-api/internal/reviewreceipts"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// realProvenanceEnv is a worker env whose provenance is a real
// workitems.Store, so attach_path / attached_direct_service come from the
// code that writes them.
type realProvenanceEnv struct {
	*workerEnv
	wi     *workitems.Store
	tenant string
}

func newRealProvenanceEnv(t *testing.T) *realProvenanceEnv {
	t.Helper()
	e := newWorkerEnv(t)
	ctx := context.Background()
	wi, err := workitems.NewStore(ctx, os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatalf("workitems.NewStore: %v", err)
	}
	tenant := fmt.Sprintf("rv917-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = e.s.pool.Exec(context.Background(), `DELETE FROM work_items WHERE tenant = $1`, tenant)
		wi.Close()
	})
	e.s.SetProvenance(wi)
	return &realProvenanceEnv{workerEnv: e, wi: wi, tenant: tenant}
}

var directService = workitems.Mutation{Actor: "service:mctl-agent", ActorDirectService: true, Surface: "cli", RequestID: "req-917"}

func (e *realProvenanceEnv) item() *workitems.WorkItem {
	e.t.Helper()
	w, _, err := e.wi.Create(context.Background(), workitems.CreateInput{Mutation: workitems.Mutation{Actor: "github:alice", Surface: "cli"},
		Tenant: e.tenant, Visibility: workitems.VisibilityTenant, OriginSurface: "cli", Title: "review me"})
	if err != nil {
		e.t.Fatal(err)
	}
	return w
}

func (e *realProvenanceEnv) attach(m workitems.Mutation, phase string) (*workitems.WorkItem, *workitems.Execution) {
	e.t.Helper()
	w := e.item()
	x, _, err := e.wi.AttachExecution(context.Background(), workitems.ExecutionInput{Mutation: m, WorkItemID: w.ID,
		Engine: workitems.EngineTemporal, EngineRef: "run-" + uuid.NewString(), Phase: phase})
	if err != nil {
		e.t.Fatalf("AttachExecution: %v", err)
	}
	return w, x
}

// ingestFor seals and ingests a worker request authored by exec, with the
// authoring facts read from its real provenance.
func (e *realProvenanceEnv) ingestFor(exec string) reviewreceipts.ReviewRequest {
	e.t.Helper()
	p, err := e.wi.ExecutionProvenance(context.Background(), exec)
	if err != nil {
		e.t.Fatal(err)
	}
	req, err := reviewreceipts.SealRequest(reviewreceipts.SealRequestInput{
		Subject: uniqueSubject("rv", "4"), Mode: reviewreceipts.ModeWorker, Nonce: "nonce-" + uuid.NewString(),
		AuthoringExecutionID: exec, AuthoringAttemptIDs: []string{p.AttemptID}, AuthoringLineageRoot: p.LineageRoot,
		CreatedAt: "2026-01-01T00:00:00Z",
	})
	if err != nil {
		e.t.Fatal(err)
	}
	raw, _ := json.Marshal(req.Dict())
	if _, _, err := e.s.IngestRequest(context.Background(), raw, Actor{Name: "svc"}); err != nil {
		e.t.Fatalf("IngestRequest: %v", err)
	}
	e.cleanupRequest(req.RequestID)
	return req
}

// T10 with real provenance: executions attached by a developer, resumed by a
// developer, attached by an agent run, and a legacy-shaped row are all
// ineligible; one attached by the platform acting directly is accepted
// (proving the refusals are the eligibility rule, not a broken fixture).
func TestSubmitWorker_EligibilityFromRecordedProvenance(t *testing.T) {
	e := newRealProvenanceEnv(t)
	ctx := context.Background()
	_, author := e.attach(directService, workitems.PhaseSucceeded)
	req := e.ingestFor(author.ID)

	developer := workitems.Mutation{Actor: "github:alice", ActorPrincipalID: "prn_alice", Surface: "cli", RequestID: "req-dev"}
	_, devAttached := e.attach(developer, workitems.PhaseRunning)

	w, _ := e.attach(directService, workitems.PhaseSucceeded)
	resumer := developer
	resumer.IdempotencyKey, resumer.RequestHash = "k-"+uuid.NewString(), "h"
	_, devResumed, _, err := e.wi.Resume(ctx, workitems.ResumeInput{Mutation: resumer, WorkItemID: w.ID,
		ExpectedStateVersion: w.StateVersion, Engine: workitems.EngineTemporal, EngineRef: "run-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("developer resume: %v", err)
	}

	agent := workitems.Mutation{Actor: "agent:implementer", ActorPrincipalID: "prn_agent", ViaExecutionID: author.ID, Surface: "cli", RequestID: "req-agent"}
	_, agentAttached := e.attach(agent, workitems.PhaseRunning)

	// Legacy: a row recorded before the columns existed, inserted with the
	// old column list so the defaults ('' / false) apply.
	_, legacy := e.attach(directService, workitems.PhaseRunning)
	lp, err := e.wi.ExecutionProvenance(ctx, legacy.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.pool.Exec(ctx, `DELETE FROM execution_provenance WHERE execution_id = $1`, legacy.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.pool.Exec(ctx, `INSERT INTO execution_provenance (execution_id, contract_version, attempt_id, lineage_root,
    engine, engine_run, parent_execution_id, root_execution_id, attached_by, attached_by_principal, recorded_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, lp.ExecutionID, lp.ContractVersion, lp.AttemptID, lp.LineageRoot, lp.Engine,
		lp.EngineRun, lp.ParentExecutionID, lp.RootExecutionID, lp.AttachedBy, lp.AttachedByPrincipal, lp.RecordedAt); err != nil {
		t.Fatalf("insert legacy row: %v", err)
	}
	if got, err := e.wi.ExecutionProvenance(ctx, legacy.ID); err != nil || got.AttachPath != "" || got.AttachedDirectService {
		t.Fatalf("legacy row reads back as %+v %v, want '' / false", got, err)
	}

	for name, exec := range map[string]string{
		"developer attach": devAttached.ID,
		"developer resume": devResumed.ID,
		"agent attach":     agentAttached.ID,
		"legacy row":       legacy.ID,
	} {
		if _, err := e.s.SubmitWorker(ctx, workerInput(req), reviewer(exec), time.Now()); !errors.Is(err, ErrReviewerIneligible) {
			t.Errorf("%s: %v, want ErrReviewerIneligible", name, err)
		}
	}
	e.assertNothingStored(req.RequestID)

	_, platform := e.attach(directService, workitems.PhaseRunning)
	rc, err := e.s.SubmitWorker(ctx, workerInput(req), reviewer(platform.ID), time.Now())
	if err != nil {
		t.Fatalf("platform-attached reviewer: %v", err)
	}
	pp, _ := e.wi.ExecutionProvenance(ctx, platform.ID)
	if rc.Receipt.ReviewerExecutionID != platform.ID || rc.Receipt.AttemptID != pp.AttemptID || rc.Receipt.LineageRoot != pp.LineageRoot {
		t.Fatalf("receipt = %+v, want the recorded provenance %+v", rc.Receipt, pp)
	}
	if r, c := e.rows(req.RequestID); r != 1 || c != 1 {
		t.Fatalf("%d receipt(s), %d consumption(s); want 1 and 1", r, c)
	}
}
