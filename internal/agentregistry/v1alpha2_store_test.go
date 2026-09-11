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
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// newV1Alpha2TestStore is newTestStore extended with the v1alpha2 tables in
// its cleanup list — TEST_DATABASE_URL-gated, same convention as the v1
// store_test.go.
func newV1Alpha2TestStore(t *testing.T) *Store {
	t.Helper()
	connStr := os.Getenv("TEST_DATABASE_URL")
	if connStr == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping Postgres-backed agentregistry v1alpha2 store test")
	}

	ctx := context.Background()
	s, err := NewStore(ctx, connStr)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	tables := []string{
		"agent_release_bindings", "agent_profile_versions", "agent_definition_versions",
		"agent_executions", "agent_promotions", "agent_releases", "agent_versions", "agent_definitions",
	}
	cleanup := func() {
		for _, table := range tables {
			_, _ = s.pool.Exec(ctx, "DELETE FROM "+table)
		}
	}
	t.Cleanup(func() {
		cleanup()
		s.pool.Close()
	})
	cleanup()
	return s
}

func newDefinitionVersion(agent, version, profileRange string) *DefinitionVersion {
	return &DefinitionVersion{
		Agent:    agent,
		Version:  version,
		SpecJSON: `{"kind":"AgentDefinition"}`,
		Owner:    "mctl-agents",
		SourceManifest: SourceManifest{
			Repo: "mctlhq/mctl-agents", Path: "agents/_manifests/" + agent + "/agent.yaml",
			GitSHA: "deadbeef", ContentHash: "sha256:test",
		},
		ProfileRange: profileRange,
	}
}

func newProfileVersion(profile, version string) *ProfileVersion {
	return &ProfileVersion{
		Profile:  profile,
		Version:  version,
		SpecJSON: `{"maxTokens":100000,"maxToolCalls":50,"timeoutSeconds":600}`,
		Owner:    "mctl-agents",
		SourceManifest: SourceManifest{
			Repo: "mctlhq/platform-gitops", Path: "agent-platform/profiles/" + profile + ".yaml",
			GitSHA: "cafebabe", ContentHash: "sha256:profile",
		},
	}
}

// ─── T2: publish paths ────────────────────────────────────────────────

func TestPublishDefinitionVersion_DuplicateConflict(t *testing.T) {
	s := newV1Alpha2TestStore(t)
	ctx := context.Background()
	if _, err := s.CreateDefinition(ctx, "issue-investigator", "", ""); err != nil {
		t.Fatalf("create definition: %v", err)
	}

	if _, err := s.PublishDefinitionVersion(ctx, newDefinitionVersion("issue-investigator", "1.0.0", ">=1.0.0")); err != nil {
		t.Fatalf("first publish: %v", err)
	}
	_, err := s.PublishDefinitionVersion(ctx, newDefinitionVersion("issue-investigator", "1.0.0", ">=1.0.0"))
	if !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("expected ErrVersionConflict, got %v", err)
	}
}

func TestPublishDefinitionVersion_UnknownAgentRejected(t *testing.T) {
	s := newV1Alpha2TestStore(t)
	ctx := context.Background()

	_, err := s.PublishDefinitionVersion(ctx, newDefinitionVersion("no-such-agent", "1.0.0", ">=1.0.0"))
	if !errors.Is(err, ErrDefinitionNotFound) {
		t.Fatalf("expected ErrDefinitionNotFound, got %v", err)
	}
}

func TestPublishDefinitionVersion_UnparseableRangeRejected(t *testing.T) {
	s := newV1Alpha2TestStore(t)
	ctx := context.Background()
	if _, err := s.CreateDefinition(ctx, "issue-investigator", "", ""); err != nil {
		t.Fatalf("create definition: %v", err)
	}

	_, err := s.PublishDefinitionVersion(ctx, newDefinitionVersion("issue-investigator", "1.0.0", "not-a-range"))
	if !errors.Is(err, ErrInvalidRange) {
		t.Fatalf("expected ErrInvalidRange, got %v", err)
	}
}

func TestPublishDefinitionVersion_MissingFieldsRejected(t *testing.T) {
	s := newV1Alpha2TestStore(t)
	ctx := context.Background()
	if _, err := s.CreateDefinition(ctx, "issue-investigator", "", ""); err != nil {
		t.Fatalf("create definition: %v", err)
	}

	d := newDefinitionVersion("issue-investigator", "1.0.0", ">=1.0.0")
	d.Owner = ""
	d.SourceManifest.GitSHA = ""
	d.SourceManifest.ContentHash = ""
	_, err := s.PublishDefinitionVersion(ctx, d)
	if err == nil {
		t.Fatal("expected an error for missing owner/gitSha/contentHash")
	}
	// All three missing fields should be named in one response.
	msg := err.Error()
	for _, field := range []string{"owner", "sourceManifest.gitSha", "sourceManifest.contentHash"} {
		if !strings.Contains(msg, field) {
			t.Errorf("expected error to name missing field %q, got: %s", field, msg)
		}
	}
}

func TestPublishProfileVersion_MissingPolicyFieldsListsAll(t *testing.T) {
	s := newV1Alpha2TestStore(t)
	ctx := context.Background()

	p := newProfileVersion("standard-investigate", "1.0.0")
	p.SpecJSON = `{}` // missing every required policy field
	_, err := s.PublishProfileVersion(ctx, p)
	if !errors.Is(err, ErrMissingPolicyFields) {
		t.Fatalf("expected ErrMissingPolicyFields, got %v", err)
	}
	for _, field := range RequiredProfilePolicyFields {
		if !strings.Contains(err.Error(), field) {
			t.Errorf("expected error to name missing field %q, got: %s", field, err.Error())
		}
	}
}

func TestPublishProfileVersion_DuplicateConflict(t *testing.T) {
	s := newV1Alpha2TestStore(t)
	ctx := context.Background()

	if _, err := s.PublishProfileVersion(ctx, newProfileVersion("standard-investigate", "1.0.0")); err != nil {
		t.Fatalf("first publish: %v", err)
	}
	_, err := s.PublishProfileVersion(ctx, newProfileVersion("standard-investigate", "1.0.0"))
	if !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("expected ErrVersionConflict, got %v", err)
	}
}

func TestLifecycleTransitionMatrix(t *testing.T) {
	s := newV1Alpha2TestStore(t)
	ctx := context.Background()
	if _, err := s.CreateDefinition(ctx, "issue-investigator", "", ""); err != nil {
		t.Fatalf("create definition: %v", err)
	}
	if _, err := s.PublishDefinitionVersion(ctx, newDefinitionVersion("issue-investigator", "1.0.0", ">=1.0.0")); err != nil {
		t.Fatalf("publish: %v", err)
	}

	// published -> disabled directly: valid.
	if _, err := s.SetDefinitionVersionLifecycle(ctx, "issue-investigator", "1.0.0", LifecycleDisabled, "bad", "tester"); err != nil {
		t.Fatalf("published -> disabled: %v", err)
	}
	// disabled -> deprecated: invalid.
	_, err := s.SetDefinitionVersionLifecycle(ctx, "issue-investigator", "1.0.0", LifecycleDeprecated, "", "tester")
	if !errors.Is(err, ErrInvalidLifecycleTransition) {
		t.Fatalf("expected ErrInvalidLifecycleTransition for disabled -> deprecated, got %v", err)
	}

	// Fresh version: published -> deprecated -> disabled is valid.
	if _, err := s.PublishDefinitionVersion(ctx, newDefinitionVersion("issue-investigator", "1.1.0", ">=1.0.0")); err != nil {
		t.Fatalf("publish 1.1.0: %v", err)
	}
	if _, err := s.SetDefinitionVersionLifecycle(ctx, "issue-investigator", "1.1.0", LifecycleDeprecated, "", "tester"); err != nil {
		t.Fatalf("published -> deprecated: %v", err)
	}
	if _, err := s.SetDefinitionVersionLifecycle(ctx, "issue-investigator", "1.1.0", LifecycleDisabled, "", "tester"); err != nil {
		t.Fatalf("deprecated -> disabled: %v", err)
	}
	// published -> published: invalid (not a real transition).
	if _, err := s.PublishDefinitionVersion(ctx, newDefinitionVersion("issue-investigator", "1.2.0", ">=1.0.0")); err != nil {
		t.Fatalf("publish 1.2.0: %v", err)
	}
	_, err = s.SetDefinitionVersionLifecycle(ctx, "issue-investigator", "1.2.0", LifecyclePublished, "", "tester")
	if !errors.Is(err, ErrInvalidLifecycleTransition) {
		t.Fatalf("expected ErrInvalidLifecycleTransition for published -> published, got %v", err)
	}
}

// ─── T3: binding happy path ───────────────────────────────────────────

func TestCreateBinding_HappyPath(t *testing.T) {
	s := newV1Alpha2TestStore(t)
	ctx := context.Background()
	if _, err := s.CreateDefinition(ctx, "issue-investigator", "", ""); err != nil {
		t.Fatalf("create definition: %v", err)
	}
	if _, err := s.PublishDefinitionVersion(ctx, newDefinitionVersion("issue-investigator", "1.4.0", ">=2.0.0 <3.0.0")); err != nil {
		t.Fatalf("publish definition: %v", err)
	}
	if _, err := s.PublishProfileVersion(ctx, newProfileVersion("standard-investigate", "2.1.0")); err != nil {
		t.Fatalf("publish profile: %v", err)
	}

	binding, err := s.CreateBinding(ctx, CreateBindingRequest{
		Agent: "issue-investigator", Environment: EnvironmentShadow,
		DefinitionVersion: "1.4.0", Profile: "standard-investigate", ProfileVersion: "2.1.0",
		BindingSource: BindingSourceRegistry, Actor: "tester",
	})
	if err != nil {
		t.Fatalf("create binding: %v", err)
	}
	if binding.Revision != 1 {
		t.Fatalf("expected revision 1, got %d", binding.Revision)
	}

	resolved, err := s.ResolveBinding(ctx, "issue-investigator", EnvironmentShadow)
	if err != nil {
		t.Fatalf("resolve binding: %v", err)
	}
	if resolved.Revision != 1 {
		t.Fatalf("expected resolved revision 1, got %d", resolved.Revision)
	}
	if resolved.Definition.Version != "1.4.0" || resolved.Profile.Version != "2.1.0" {
		t.Fatalf("unexpected resolved pair: %+v", resolved)
	}
	if resolved.Definition.SourceManifest.GitSHA == "" || resolved.Profile.SourceManifest.GitSHA == "" {
		t.Fatal("expected both source manifests to be populated")
	}
	if resolved.BindingSource != BindingSourceRegistry {
		t.Fatalf("expected bindingSource registry, got %q", resolved.BindingSource)
	}
}

// ─── T4: binding rejections ───────────────────────────────────────────

func TestCreateBinding_Rejections(t *testing.T) {
	s := newV1Alpha2TestStore(t)
	ctx := context.Background()
	if _, err := s.CreateDefinition(ctx, "issue-investigator", "", ""); err != nil {
		t.Fatalf("create definition: %v", err)
	}
	if _, err := s.PublishDefinitionVersion(ctx, newDefinitionVersion("issue-investigator", "1.0.0", ">=2.0.0 <3.0.0")); err != nil {
		t.Fatalf("publish definition: %v", err)
	}
	if _, err := s.PublishProfileVersion(ctx, newProfileVersion("standard-investigate", "2.1.0")); err != nil {
		t.Fatalf("publish profile: %v", err)
	}
	if _, err := s.PublishProfileVersion(ctx, newProfileVersion("standard-investigate", "9.9.9")); err != nil {
		t.Fatalf("publish incompatible profile: %v", err)
	}

	assertNoRowsAppended := func(t *testing.T) {
		t.Helper()
		bindings, err := s.ListBindings(ctx, "issue-investigator", EnvironmentShadow)
		if err != nil {
			t.Fatalf("list bindings: %v", err)
		}
		if len(bindings) != 0 {
			t.Fatalf("expected no bindings to be appended, got %d", len(bindings))
		}
	}

	t.Run("incompatible range", func(t *testing.T) {
		_, err := s.CreateBinding(ctx, CreateBindingRequest{
			Agent: "issue-investigator", Environment: EnvironmentShadow,
			DefinitionVersion: "1.0.0", Profile: "standard-investigate", ProfileVersion: "9.9.9",
			BindingSource: BindingSourceRegistry,
		})
		if !errors.Is(err, ErrIncompatibleProfile) {
			t.Fatalf("expected ErrIncompatibleProfile, got %v", err)
		}
		assertNoRowsAppended(t)
	})

	t.Run("deprecated definition", func(t *testing.T) {
		if _, err := s.SetDefinitionVersionLifecycle(ctx, "issue-investigator", "1.0.0", LifecycleDeprecated, "", "tester"); err != nil {
			t.Fatalf("deprecate: %v", err)
		}
		_, err := s.CreateBinding(ctx, CreateBindingRequest{
			Agent: "issue-investigator", Environment: EnvironmentShadow,
			DefinitionVersion: "1.0.0", Profile: "standard-investigate", ProfileVersion: "2.1.0",
			BindingSource: BindingSourceRegistry,
		})
		if !errors.Is(err, ErrVersionDeprecated) {
			t.Fatalf("expected ErrVersionDeprecated, got %v", err)
		}
		assertNoRowsAppended(t)
	})

	t.Run("disabled profile", func(t *testing.T) {
		if _, err := s.PublishDefinitionVersion(ctx, newDefinitionVersion("issue-investigator", "1.1.0", ">=2.0.0 <3.0.0")); err != nil {
			t.Fatalf("publish 1.1.0: %v", err)
		}
		if _, err := s.SetProfileVersionLifecycle(ctx, "standard-investigate", "2.1.0", LifecycleDisabled, "", "tester"); err != nil {
			t.Fatalf("disable profile: %v", err)
		}
		_, err := s.CreateBinding(ctx, CreateBindingRequest{
			Agent: "issue-investigator", Environment: EnvironmentShadow,
			DefinitionVersion: "1.1.0", Profile: "standard-investigate", ProfileVersion: "2.1.0",
			BindingSource: BindingSourceRegistry,
		})
		if !errors.Is(err, ErrVersionDisabled) {
			t.Fatalf("expected ErrVersionDisabled, got %v", err)
		}
		assertNoRowsAppended(t)
	})

	t.Run("missing version", func(t *testing.T) {
		_, err := s.CreateBinding(ctx, CreateBindingRequest{
			Agent: "issue-investigator", Environment: EnvironmentShadow,
			DefinitionVersion: "9.9.9", Profile: "standard-investigate", ProfileVersion: "2.1.0",
			BindingSource: BindingSourceRegistry,
		})
		if !errors.Is(err, ErrDefinitionVersionNotFound) {
			t.Fatalf("expected ErrDefinitionVersionNotFound, got %v", err)
		}
		assertNoRowsAppended(t)
	})

	t.Run("compatibility-fixture source", func(t *testing.T) {
		if _, err := s.PublishProfileVersion(ctx, newProfileVersion("standard-investigate", "2.2.0")); err != nil {
			t.Fatalf("publish 2.2.0: %v", err)
		}
		_, err := s.CreateBinding(ctx, CreateBindingRequest{
			Agent: "issue-investigator", Environment: EnvironmentShadow,
			DefinitionVersion: "1.1.0", Profile: "standard-investigate", ProfileVersion: "2.2.0",
			BindingSource: BindingSourceCompatibilityFixture,
		})
		if !errors.Is(err, ErrFixtureNotPromotable) {
			t.Fatalf("expected ErrFixtureNotPromotable, got %v", err)
		}
		assertNoRowsAppended(t)
	})

	t.Run("invalid environment", func(t *testing.T) {
		_, err := s.CreateBinding(ctx, CreateBindingRequest{
			Agent: "issue-investigator", Environment: "staging",
			DefinitionVersion: "1.1.0", Profile: "standard-investigate", ProfileVersion: "2.2.0",
			BindingSource: BindingSourceRegistry,
		})
		if !errors.Is(err, ErrInvalidEnvironment) {
			t.Fatalf("expected ErrInvalidEnvironment, got %v", err)
		}
		assertNoRowsAppended(t)
	})
}

// ─── T5: append-only history and rollback ─────────────────────────────

func TestBindingHistory_AppendOnlyAndRollback(t *testing.T) {
	s := newV1Alpha2TestStore(t)
	ctx := context.Background()
	if _, err := s.CreateDefinition(ctx, "issue-investigator", "", ""); err != nil {
		t.Fatalf("create definition: %v", err)
	}
	if _, err := s.PublishDefinitionVersion(ctx, newDefinitionVersion("issue-investigator", "1.0.0", ">=1.0.0 <3.0.0")); err != nil {
		t.Fatalf("publish 1.0.0: %v", err)
	}
	if _, err := s.PublishDefinitionVersion(ctx, newDefinitionVersion("issue-investigator", "2.0.0", ">=1.0.0 <3.0.0")); err != nil {
		t.Fatalf("publish 2.0.0: %v", err)
	}
	if _, err := s.PublishProfileVersion(ctx, newProfileVersion("standard-investigate", "1.0.0")); err != nil {
		t.Fatalf("publish profile 1.0.0: %v", err)
	}
	if _, err := s.PublishProfileVersion(ctx, newProfileVersion("standard-investigate", "2.0.0")); err != nil {
		t.Fatalf("publish profile 2.0.0: %v", err)
	}

	bindA, err := s.CreateBinding(ctx, CreateBindingRequest{
		Agent: "issue-investigator", Environment: EnvironmentShadow,
		DefinitionVersion: "1.0.0", Profile: "standard-investigate", ProfileVersion: "1.0.0",
		BindingSource: BindingSourceRegistry,
	})
	if err != nil {
		t.Fatalf("bind A: %v", err)
	}
	if bindA.Revision != 1 {
		t.Fatalf("expected revision 1, got %d", bindA.Revision)
	}

	bindB, err := s.CreateBinding(ctx, CreateBindingRequest{
		Agent: "issue-investigator", Environment: EnvironmentShadow,
		DefinitionVersion: "2.0.0", Profile: "standard-investigate", ProfileVersion: "2.0.0",
		BindingSource: BindingSourceRegistry,
	})
	if err != nil {
		t.Fatalf("bind B: %v", err)
	}
	if bindB.Revision != 2 {
		t.Fatalf("expected revision 2, got %d", bindB.Revision)
	}

	rolledBack, err := s.RollbackBinding(ctx, "issue-investigator", EnvironmentShadow, 1, "revert B", "tester")
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if rolledBack.Revision != 3 {
		t.Fatalf("expected revision 3, got %d", rolledBack.Revision)
	}
	if rolledBack.RollbackOf == nil || *rolledBack.RollbackOf != bindA.ID {
		t.Fatalf("expected rollback_of to point at revision 1's id (%d), got %v", bindA.ID, rolledBack.RollbackOf)
	}
	if rolledBack.DefinitionVersion != "1.0.0" || rolledBack.ProfileVersion != "1.0.0" {
		t.Fatalf("expected rollback to repeat revision 1's pair, got %+v", rolledBack)
	}

	all, err := s.ListBindings(ctx, "issue-investigator", EnvironmentShadow)
	if err != nil {
		t.Fatalf("list bindings: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3 revisions (1, 2, 3), got %d", len(all))
	}

	resolved, err := s.ResolveBinding(ctx, "issue-investigator", EnvironmentShadow)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if resolved.Revision != 3 {
		t.Fatalf("expected resolve to return revision 3, got %d", resolved.Revision)
	}

	// Disable revision 1's profile, then rollback to it must be rejected.
	if _, err := s.SetProfileVersionLifecycle(ctx, "standard-investigate", "1.0.0", LifecycleDisabled, "", "tester"); err != nil {
		t.Fatalf("disable profile 1.0.0: %v", err)
	}
	_, err = s.RollbackBinding(ctx, "issue-investigator", EnvironmentShadow, 1, "should fail", "tester")
	if !errors.Is(err, ErrVersionDisabled) {
		t.Fatalf("expected ErrVersionDisabled rolling back to a disabled pair, got %v", err)
	}
}

// ─── T6: concurrency ───────────────────────────────────────────────────

func TestCreateBinding_ConcurrentBindsProduceGaplessRevisions(t *testing.T) {
	connStr := os.Getenv("TEST_DATABASE_URL")
	if connStr == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping Postgres-backed concurrency test")
	}
	s := newV1Alpha2TestStore(t)
	ctx := context.Background()
	if _, err := s.CreateDefinition(ctx, "issue-investigator", "", ""); err != nil {
		t.Fatalf("create definition: %v", err)
	}
	if _, err := s.PublishDefinitionVersion(ctx, newDefinitionVersion("issue-investigator", "1.0.0", ">=1.0.0")); err != nil {
		t.Fatalf("publish definition: %v", err)
	}
	if _, err := s.PublishProfileVersion(ctx, newProfileVersion("standard-investigate", "1.0.0")); err != nil {
		t.Fatalf("publish profile: %v", err)
	}

	const n = 10
	revisions := make([]int, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			// A separate pool per goroutine avoids serializing on pgxpool's
			// own connection acquisition in a way that would mask a real
			// database-level race; each still targets the same underlying
			// Postgres database and the same advisory lock key.
			pool, err := pgxpool.New(ctx, connStr)
			if err != nil {
				errs[i] = err
				return
			}
			defer pool.Close()
			localStore := &Store{pool: pool}
			b, err := localStore.CreateBinding(ctx, CreateBindingRequest{
				Agent: "issue-investigator", Environment: EnvironmentShadow,
				DefinitionVersion: "1.0.0", Profile: "standard-investigate", ProfileVersion: "1.0.0",
				BindingSource: BindingSourceRegistry, Actor: "concurrent",
			})
			if err != nil {
				errs[i] = err
				return
			}
			revisions[i] = b.Revision
		}(i)
	}
	wg.Wait()

	seen := map[int]bool{}
	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
		if seen[revisions[i]] {
			t.Fatalf("duplicate revision %d", revisions[i])
		}
		seen[revisions[i]] = true
	}
	for rev := 1; rev <= n; rev++ {
		if !seen[rev] {
			t.Fatalf("expected gapless revisions 1..%d, missing %d", n, rev)
		}
	}
}

// ─── T13: schema idempotency ───────────────────────────────────────────

func TestNewStore_SchemaIsIdempotent(t *testing.T) {
	connStr := os.Getenv("TEST_DATABASE_URL")
	if connStr == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping Postgres-backed schema idempotency test")
	}
	ctx := context.Background()

	first, err := NewStore(ctx, connStr)
	if err != nil {
		t.Fatalf("first NewStore: %v", err)
	}
	defer first.pool.Close()

	if _, err := first.CreateDefinition(ctx, "schema-idempotency-agent", "", ""); err != nil {
		t.Fatalf("create definition: %v", err)
	}
	t.Cleanup(func() {
		_, _ = first.pool.Exec(ctx, "DELETE FROM agent_definitions WHERE name = 'schema-idempotency-agent'")
	})

	// Re-running NewStore against the same database must not error and must
	// not disturb the row just inserted.
	second, err := NewStore(ctx, connStr)
	if err != nil {
		t.Fatalf("second NewStore: %v", err)
	}
	defer second.pool.Close()

	var count int
	if err := second.pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM agent_definitions WHERE name = 'schema-idempotency-agent'",
	).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected the row to survive a second NewStore call, got count=%d", count)
	}
}
