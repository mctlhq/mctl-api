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

package agentregistry

import (
	"context"
	"errors"
	"os"
	"testing"
)

// newTestStore connects to a real Postgres instance, same convention as
// alerts.newTestStore: skips when TEST_DATABASE_URL is unset since this repo
// has no Postgres service in CI.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	connStr := os.Getenv("TEST_DATABASE_URL")
	if connStr == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping Postgres-backed agentregistry store test")
	}

	ctx := context.Background()
	s, err := NewStore(ctx, connStr)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() {
		_, _ = s.pool.Exec(ctx, "DELETE FROM agent_executions")
		_, _ = s.pool.Exec(ctx, "DELETE FROM agent_promotions")
		_, _ = s.pool.Exec(ctx, "DELETE FROM agent_releases")
		_, _ = s.pool.Exec(ctx, "DELETE FROM agent_versions")
		_, _ = s.pool.Exec(ctx, "DELETE FROM agent_definitions")
		s.pool.Close()
	})

	// Isolate from any rows left by other tests/runs.
	for _, table := range []string{"agent_executions", "agent_promotions", "agent_releases", "agent_versions", "agent_definitions"} {
		if _, err := s.pool.Exec(ctx, "DELETE FROM "+table); err != nil {
			t.Fatalf("cleanup %s: %v", table, err)
		}
	}
	return s
}

func newVersion(agent, version string) *AgentVersion {
	return &AgentVersion{
		Agent:           agent,
		Version:         version,
		ManifestJSON:    `{"apiVersion":"agents.mctl.ai/v1alpha1"}`,
		GitSHA:          "deadbeef",
		ImageRepository: "ghcr.io/mctlhq/mctl-agents",
		PromptHash:      "sha256:test",
	}
}

func TestCreateDefinition_IsIdempotentAndPreservesCreatedAt(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	first, err := s.CreateDefinition(ctx, "issue-investigator", "first description", "mctl-agents")
	if err != nil {
		t.Fatalf("first create: %v", err)
	}

	second, err := s.CreateDefinition(ctx, "issue-investigator", "updated description", "mctl-agents")
	if err != nil {
		t.Fatalf("second create: %v", err)
	}

	if second.Description != "updated description" {
		t.Fatalf("expected description to update in place, got %q", second.Description)
	}
	if !second.CreatedAt.Equal(first.CreatedAt) {
		t.Fatalf("expected created_at to survive a republish, got %v then %v", first.CreatedAt, second.CreatedAt)
	}
}

func TestPublishVersion_DuplicateRejected(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, err := s.CreateDefinition(ctx, "shepherd", "", ""); err != nil {
		t.Fatalf("create definition: %v", err)
	}

	if _, err := s.PublishVersion(ctx, newVersion("shepherd", "1.0.0")); err != nil {
		t.Fatalf("first publish: %v", err)
	}

	_, err := s.PublishVersion(ctx, newVersion("shepherd", "1.0.0"))
	if !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("expected ErrVersionConflict republishing the same version, got %v", err)
	}
}

func TestPublishVersion_UnknownAgentRejected(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	_, err := s.PublishVersion(ctx, newVersion("no-such-agent", "1.0.0"))
	if !errors.Is(err, ErrDefinitionNotFound) {
		t.Fatalf("expected ErrDefinitionNotFound publishing a version for an undeclared agent, got %v", err)
	}
}

func TestPromoteRelease_ThenResolve(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, err := s.CreateDefinition(ctx, "mentor", "", ""); err != nil {
		t.Fatalf("create definition: %v", err)
	}
	if _, err := s.PublishVersion(ctx, newVersion("mentor", "1.0.0")); err != nil {
		t.Fatalf("publish version: %v", err)
	}

	release, err := s.PromoteRelease(ctx, "mentor", EnvironmentProduction, "1.0.0", "initial release", "mashkovd")
	if err != nil {
		t.Fatalf("promote: %v", err)
	}
	if release.Version != "1.0.0" || release.TrafficWeight != 100 {
		t.Fatalf("unexpected release: %+v", release)
	}

	resolved, err := s.ResolveRelease(ctx, "mentor", EnvironmentProduction)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if resolved.Version != "1.0.0" {
		t.Fatalf("expected resolve to return the promoted version, got %q", resolved.Version)
	}
}

func TestPromoteRelease_UnknownVersionRejected(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, err := s.CreateDefinition(ctx, "mentor", "", ""); err != nil {
		t.Fatalf("create definition: %v", err)
	}

	_, err := s.PromoteRelease(ctx, "mentor", EnvironmentProduction, "9.9.9", "", "mashkovd")
	if !errors.Is(err, ErrVersionNotFound) {
		t.Fatalf("expected ErrVersionNotFound promoting an unpublished version, got %v", err)
	}
}

func TestPromoteRelease_InvalidEnvironmentRejected(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, err := s.CreateDefinition(ctx, "mentor", "", ""); err != nil {
		t.Fatalf("create definition: %v", err)
	}
	if _, err := s.PublishVersion(ctx, newVersion("mentor", "1.0.0")); err != nil {
		t.Fatalf("publish version: %v", err)
	}

	_, err := s.PromoteRelease(ctx, "mentor", "staging", "1.0.0", "", "mashkovd")
	if !errors.Is(err, ErrInvalidEnvironment) {
		t.Fatalf("expected ErrInvalidEnvironment for an environment outside {production, shadow}, got %v", err)
	}
}

func TestRollback_RevertsToPriorVersion(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, err := s.CreateDefinition(ctx, "implementer", "", ""); err != nil {
		t.Fatalf("create definition: %v", err)
	}
	if _, err := s.PublishVersion(ctx, newVersion("implementer", "1.0.0")); err != nil {
		t.Fatalf("publish 1.0.0: %v", err)
	}
	if _, err := s.PublishVersion(ctx, newVersion("implementer", "2.0.0")); err != nil {
		t.Fatalf("publish 2.0.0: %v", err)
	}

	if _, err := s.PromoteRelease(ctx, "implementer", EnvironmentProduction, "1.0.0", "initial", "mashkovd"); err != nil {
		t.Fatalf("promote 1.0.0: %v", err)
	}
	if _, err := s.PromoteRelease(ctx, "implementer", EnvironmentProduction, "2.0.0", "bad prompt edit", "mashkovd"); err != nil {
		t.Fatalf("promote 2.0.0: %v", err)
	}

	rolledBack, err := s.Rollback(ctx, "implementer", EnvironmentProduction, "reverting bad prompt edit", "mashkovd")
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if rolledBack.Version != "1.0.0" {
		t.Fatalf("expected rollback to revert to 1.0.0, got %q", rolledBack.Version)
	}

	promotions, err := s.ListPromotions(ctx, "implementer", EnvironmentProduction)
	if err != nil {
		t.Fatalf("list promotions: %v", err)
	}
	if len(promotions) != 3 {
		t.Fatalf("expected 3 promotion rows (2 forward + 1 rollback), got %d", len(promotions))
	}
	if promotions[0].RollbackOf == nil {
		t.Fatalf("expected the most recent promotion row to record rollback_of, got nil")
	}
}

func TestRollback_NoHistoryRejected(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, err := s.CreateDefinition(ctx, "implementer", "", ""); err != nil {
		t.Fatalf("create definition: %v", err)
	}

	_, err := s.Rollback(ctx, "implementer", EnvironmentProduction, "", "mashkovd")
	if !errors.Is(err, ErrNoRollbackTarget) {
		t.Fatalf("expected ErrNoRollbackTarget with no promotion history, got %v", err)
	}
}

func TestRollback_OnlyOnePromotionRejected(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, err := s.CreateDefinition(ctx, "implementer", "", ""); err != nil {
		t.Fatalf("create definition: %v", err)
	}
	if _, err := s.PublishVersion(ctx, newVersion("implementer", "1.0.0")); err != nil {
		t.Fatalf("publish 1.0.0: %v", err)
	}
	if _, err := s.PromoteRelease(ctx, "implementer", EnvironmentProduction, "1.0.0", "initial", "mashkovd"); err != nil {
		t.Fatalf("promote 1.0.0: %v", err)
	}

	_, err := s.Rollback(ctx, "implementer", EnvironmentProduction, "", "mashkovd")
	if !errors.Is(err, ErrNoRollbackTarget) {
		t.Fatalf("expected ErrNoRollbackTarget with only one promotion (nothing before it), got %v", err)
	}
}

func TestCreateDefinition_BlankFieldsDoNotWipeExistingValues(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, err := s.CreateDefinition(ctx, "mentor", "digest writer", "mctl-agents"); err != nil {
		t.Fatalf("first create: %v", err)
	}

	// Republishing with blank description/owner (e.g. a CI job that only
	// knows the name) must not blank out what's already stored.
	second, err := s.CreateDefinition(ctx, "mentor", "", "")
	if err != nil {
		t.Fatalf("second create: %v", err)
	}
	if second.Description != "digest writer" {
		t.Fatalf("expected description to survive a blank republish, got %q", second.Description)
	}
	if second.Owner != "mctl-agents" {
		t.Fatalf("expected owner to survive a blank republish, got %q", second.Owner)
	}
}

func TestPromoteRelease_RetryIsIdempotentAndPreservesRollbackHistory(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, err := s.CreateDefinition(ctx, "implementer", "", ""); err != nil {
		t.Fatalf("create definition: %v", err)
	}
	if _, err := s.PublishVersion(ctx, newVersion("implementer", "1.0.0")); err != nil {
		t.Fatalf("publish 1.0.0: %v", err)
	}
	if _, err := s.PublishVersion(ctx, newVersion("implementer", "2.0.0")); err != nil {
		t.Fatalf("publish 2.0.0: %v", err)
	}

	if _, err := s.PromoteRelease(ctx, "implementer", EnvironmentProduction, "1.0.0", "initial", "mashkovd"); err != nil {
		t.Fatalf("promote 1.0.0: %v", err)
	}
	if _, err := s.PromoteRelease(ctx, "implementer", EnvironmentProduction, "2.0.0", "prompt edit", "mashkovd"); err != nil {
		t.Fatalf("promote 2.0.0: %v", err)
	}

	// A client retries the same promotion after losing the response —
	// must be a no-op: no new promotion row, and in particular no row
	// whose from_version equals its own to_version (which would make
	// Rollback resolve right back to 2.0.0 instead of the real prior
	// release, 1.0.0).
	retried, err := s.PromoteRelease(ctx, "implementer", EnvironmentProduction, "2.0.0", "prompt edit", "mashkovd")
	if err != nil {
		t.Fatalf("retried promote: %v", err)
	}
	if retried.Version != "2.0.0" {
		t.Fatalf("expected retried promote to report the already-current version, got %q", retried.Version)
	}

	promotions, err := s.ListPromotions(ctx, "implementer", EnvironmentProduction)
	if err != nil {
		t.Fatalf("list promotions: %v", err)
	}
	if len(promotions) != 2 {
		t.Fatalf("expected the retried promotion to add no new row (still 2), got %d", len(promotions))
	}

	rolledBack, err := s.Rollback(ctx, "implementer", EnvironmentProduction, "reverting prompt edit", "mashkovd")
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if rolledBack.Version != "1.0.0" {
		t.Fatalf("expected rollback to still revert to the real prior release 1.0.0, got %q", rolledBack.Version)
	}
}

func TestResolveRelease_NotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, err := s.CreateDefinition(ctx, "implementer", "", ""); err != nil {
		t.Fatalf("create definition: %v", err)
	}

	_, err := s.ResolveRelease(ctx, "implementer", EnvironmentProduction)
	if !errors.Is(err, ErrReleaseNotFound) {
		t.Fatalf("expected ErrReleaseNotFound before any promotion, got %v", err)
	}
}

func TestRecordExecution_UnregisteredAgentSucceedsWithEmptyVersion(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// No CreateDefinition call — this is the case that matters: a
	// DevLoopWorkflow step ran before this agent was ever registered.
	execution, err := s.RecordExecution(ctx, &AgentExecution{
		TemporalWorkflowID: "dev-loop-mctlhq-mctl-telegram-1",
		Agent:              "issue-investigator",
		Environment:        EnvironmentProduction,
		ArgoWorkflowName:   "mctl-agents-investigate-ab12cd34",
		Phase:              "Succeeded",
	})
	if err != nil {
		t.Fatalf("record execution: %v", err)
	}
	if execution.Version != "" || execution.ImageRef != "" {
		t.Fatalf("expected empty version/image_ref for an unregistered agent, got version=%q image_ref=%q",
			execution.Version, execution.ImageRef)
	}
	if execution.ID == 0 {
		t.Fatal("expected a non-zero generated ID")
	}
}

func TestListExecutions_FiltersByAgentWorkflowAndOrdersNewestFirst(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Three distinct steps for workflow dev-loop-a: two issue-investigator
	// attempts (distinct argo_workflow_name — a real retry-of-the-whole-step
	// scenario, not a Temporal activity retry) and one implementer step.
	for i, argoWorkflow := range []string{"wf-investigator-1", "wf-investigator-2"} {
		if _, err := s.RecordExecution(ctx, &AgentExecution{
			TemporalWorkflowID: "dev-loop-a",
			Agent:              "issue-investigator",
			Environment:        EnvironmentProduction,
			ArgoWorkflowName:   argoWorkflow,
			Phase:              "Succeeded",
		}); err != nil {
			t.Fatalf("record execution %d: %v", i, err)
		}
	}
	if _, err := s.RecordExecution(ctx, &AgentExecution{
		TemporalWorkflowID: "dev-loop-a",
		Agent:              "implementer",
		Environment:        EnvironmentProduction,
		ArgoWorkflowName:   "wf-implementer-a",
		Phase:              "Succeeded",
	}); err != nil {
		t.Fatalf("record implementer execution for dev-loop-a: %v", err)
	}
	// A different workflow entirely.
	if _, err := s.RecordExecution(ctx, &AgentExecution{
		TemporalWorkflowID: "dev-loop-b",
		Agent:              "issue-investigator",
		Environment:        EnvironmentProduction,
		ArgoWorkflowName:   "wf-investigator-b",
		Phase:              "Succeeded",
	}); err != nil {
		t.Fatalf("record execution for dev-loop-b: %v", err)
	}

	byAgent, err := s.ListExecutions(ctx, "issue-investigator", "", 0)
	if err != nil {
		t.Fatalf("list executions by agent: %v", err)
	}
	if len(byAgent) != 3 {
		t.Fatalf("expected 3 issue-investigator executions across both workflows, got %d", len(byAgent))
	}
	if byAgent[0].ArgoWorkflowName != "wf-investigator-b" {
		t.Fatalf("expected newest-first ordering, got %q first", byAgent[0].ArgoWorkflowName)
	}

	byWorkflow, err := s.ListExecutions(ctx, "", "dev-loop-a", 0)
	if err != nil {
		t.Fatalf("list executions by workflow: %v", err)
	}
	if len(byWorkflow) != 3 {
		t.Fatalf("expected 3 steps for dev-loop-a (2 investigate attempts + implement), got %d", len(byWorkflow))
	}

	byBoth, err := s.ListExecutions(ctx, "implementer", "dev-loop-a", 0)
	if err != nil {
		t.Fatalf("list executions by agent+workflow: %v", err)
	}
	if len(byBoth) != 1 || byBoth[0].ArgoWorkflowName != "wf-implementer-a" {
		t.Fatalf("expected exactly the implementer step of dev-loop-a, got %+v", byBoth)
	}

	all, err := s.ListExecutions(ctx, "", "", 0)
	if err != nil {
		t.Fatalf("list executions unfiltered: %v", err)
	}
	if len(all) != 4 {
		t.Fatalf("expected 4 executions total, got %d", len(all))
	}
}

func TestRecordExecution_RetryOfSameStepUpdatesInPlace(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	first, err := s.RecordExecution(ctx, &AgentExecution{
		TemporalWorkflowID: "dev-loop-a",
		Agent:              "issue-investigator",
		Environment:        EnvironmentProduction,
		ArgoWorkflowName:   "wf-investigator-1",
		Phase:              "Succeeded",
	})
	if err != nil {
		t.Fatalf("first record: %v", err)
	}

	// Simulate a Temporal at-least-once retry of the SAME record_execution
	// activity invocation: identical (temporal_workflow_id, agent,
	// argo_workflow_name), same phase.
	retried, err := s.RecordExecution(ctx, &AgentExecution{
		TemporalWorkflowID: "dev-loop-a",
		Agent:              "issue-investigator",
		Environment:        EnvironmentProduction,
		ArgoWorkflowName:   "wf-investigator-1",
		Phase:              "Succeeded",
	})
	if err != nil {
		t.Fatalf("retried record: %v", err)
	}
	if retried.ID != first.ID {
		t.Fatalf("expected the retry to update the same row (id %d), got a new id %d", first.ID, retried.ID)
	}

	all, err := s.ListExecutions(ctx, "", "dev-loop-a", 0)
	if err != nil {
		t.Fatalf("list executions: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("expected the retry to NOT create a duplicate row, got %d rows", len(all))
	}
}

func TestRecordExecution_InvalidEnvironmentRejected(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	_, err := s.RecordExecution(ctx, &AgentExecution{
		TemporalWorkflowID: "dev-loop-a",
		Agent:              "issue-investigator",
		Environment:        "staging",
		ArgoWorkflowName:   "wf-investigator-1",
		Phase:              "Succeeded",
	})
	if !errors.Is(err, ErrInvalidEnvironment) {
		t.Fatalf("expected ErrInvalidEnvironment, got %v", err)
	}
}
