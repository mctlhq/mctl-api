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
	"io/fs"
	"os"
	"regexp"
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

	// Deprecating (not disabling) revision 2's definition must NOT block
	// rolling back to it: RollbackBinding intentionally uses
	// validateBindingPairNotDisabled instead of CreateBinding's stricter
	// validateBindingPair, so a deprecated pair is still restorable.
	if _, err := s.SetDefinitionVersionLifecycle(ctx, "issue-investigator", "2.0.0", LifecycleDeprecated, "", "tester"); err != nil {
		t.Fatalf("deprecate definition 2.0.0: %v", err)
	}
	rolledBackDeprecated, err := s.RollbackBinding(ctx, "issue-investigator", EnvironmentShadow, 2, "restore deprecated pair", "tester")
	if err != nil {
		t.Fatalf("expected rollback to a deprecated pair to succeed, got error: %v", err)
	}
	if rolledBackDeprecated.DefinitionVersion != "2.0.0" || rolledBackDeprecated.ProfileVersion != "2.0.0" {
		t.Fatalf("expected rollback to repeat revision 2's pair, got %+v", rolledBackDeprecated)
	}
	if rolledBackDeprecated.RollbackOf == nil || *rolledBackDeprecated.RollbackOf != bindB.ID {
		t.Fatalf("expected rollback_of to point at revision 2's id (%d), got %v", bindB.ID, rolledBackDeprecated.RollbackOf)
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

// The three tests below run without TEST_DATABASE_URL on purpose. Every other
// test in this file is Postgres-gated and skips silently when the variable is
// unset, so a behaviour that is only covered there is, in practice, covered by
// nothing on a developer machine or in a CI job without a database. All three
// paths below reject before the store touches its pool, so a zero-value Store
// is enough to exercise them.

func TestValidateProfileSpec_ExplicitNullCountsAsMissing(t *testing.T) {
	// An explicit null is the half of this rule that the empty-object case
	// does not reach: the key is present, so a plain presence check passes it.
	missing, err := validateProfileSpec(`{"maxTokens":null,"maxToolCalls":50,"timeoutSeconds":600}`)
	if err != nil {
		t.Fatalf("validateProfileSpec: %v", err)
	}
	if len(missing) != 1 || missing[0] != "maxTokens" {
		t.Fatalf("expected exactly maxTokens to be missing, got %v", missing)
	}

	missing, err = validateProfileSpec(`{"maxTokens":100000,"maxToolCalls":50,"timeoutSeconds":600}`)
	if err != nil {
		t.Fatalf("validateProfileSpec: %v", err)
	}
	if len(missing) != 0 {
		t.Fatalf("expected no missing fields, got %v", missing)
	}
}

func TestValidateProfileSpec_NonObjectIsClientError(t *testing.T) {
	// Valid JSON that is not an object used to reach the caller with no
	// sentinel, which the handler's default arm reported as a 500.
	for _, spec := range []string{`[1,2]`, `42`, `"text"`, `null`, `not json`} {
		_, err := validateProfileSpec(spec)
		if !errors.Is(err, ErrInvalidSpec) {
			t.Errorf("validateProfileSpec(%q): expected ErrInvalidSpec, got %v", spec, err)
		}
	}
}

func TestPublishProfileVersion_RejectsAnUnparseableVersionBeforeTheDatabase(t *testing.T) {
	// The version is parsed at publish time, ahead of every query, so a
	// zero-value Store reaches the check without a pool.
	s := &Store{}
	p := newProfileVersion("standard-investigate", "1.x")
	if _, err := s.PublishProfileVersion(context.Background(), p); !errors.Is(err, ErrInvalidRange) {
		t.Fatalf("expected ErrInvalidRange for an unparseable version, got %v", err)
	}
}

// TestSentinelsListsEveryExportedSentinel is what makes Sentinels a list
// rather than a second hand-kept copy: it reads this package's own source and
// fails if an `Err... = errors.New(...)` declaration is missing from the map.
// Without it, adding a sentinel and forgetting the map leaves the API layer's
// mapping guard green while the new error falls through to a 500.
func TestSentinelsListsEveryExportedSentinel(t *testing.T) {
	pkg := os.DirFS(".")
	entries, err := fs.ReadDir(pkg, ".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	// Matches both a declaration inside a `var (...)` block and a top-level
	// `var Err... = errors.New(...)`; requiring only leading whitespace would
	// miss the second shape, and the count check cannot notice what the
	// pattern never saw.
	declared := regexp.MustCompile(`(?m)^\s*(?:var\s+)?(Err[A-Za-z0-9_]*)\s*=\s*errors\.New\(`)
	found := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		// Read through a directory FS rather than by path: the name comes
		// from ReadDir, but gosec cannot see that, and a rooted FS is the
		// honest way to say the read cannot leave this package.
		src, err := fs.ReadFile(pkg, name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for _, m := range declared.FindAllStringSubmatch(string(src), -1) {
			found++
			if _, ok := Sentinels[m[1]]; !ok {
				t.Errorf("%s declares %s but Sentinels does not list it, so nothing checks that the API maps it", name, m[1])
			}
		}
	}
	if found == 0 {
		t.Fatal("scanned the package and found no sentinel declarations, so this guard proves nothing")
	}
	if found != len(Sentinels) {
		t.Errorf("Sentinels has %d entries but the package declares %d sentinels", len(Sentinels), found)
	}
}

// TestPublishDefinitionVersion_RejectsAnUnparseableVersionBeforeTheDatabase
// pins the half of the publish-time semver check that only the profile path
// had: a definition version was written unparsed, so "1.2" or "v1.0.0"
// persisted and every later range comparison against it was undefined.
func TestPublishDefinitionVersion_RejectsAnUnparseableVersionBeforeTheDatabase(t *testing.T) {
	// Both parses happen ahead of every query, so a zero-value Store is
	// enough to reach them without a pool.
	s := &Store{}
	for _, version := range []string{"1.2", "v1.0.0", "latest", ""} {
		d := newDefinitionVersion("issue-investigator", version, ">=1.0.0 <2.0.0")
		if _, err := s.PublishDefinitionVersion(context.Background(), d); !errors.Is(err, ErrInvalidRange) {
			t.Errorf("version %q: expected ErrInvalidRange, got %v", version, err)
		}
	}
	// The positive case cannot run here — a well-formed version reaches the
	// pool, which a zero-value Store does not have. It is covered by the
	// Postgres-gated TestPublishDefinitionVersion_DuplicateConflict, which
	// publishes 1.0.0 successfully.
}

// TestMissingRequiredFields_IsOrdered pins the order of the message a client
// reads: the helper ranges over a map, so two missing fields came back in
// either order between runs.
func TestMissingRequiredFields_IsOrdered(t *testing.T) {
	fields := map[string]string{"owner": "", "sourceManifest.gitSha": "", "sourceManifest.contentHash": "", "present": "x"}
	want := []string{"owner", "sourceManifest.contentHash", "sourceManifest.gitSha"}
	for i := 0; i < 20; i++ {
		got := missingRequiredFields(fields)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("run %d: got %v, want %v", i, got, want)
		}
	}
}

// TestResolveBinding_UnknownAgentIsDefinitionNotFound pins the distinction
// docs/agent-platform-registry.md draws between the two 404s on a resolve:
// only the binding table was consulted, so an agent that was never declared
// answered "no binding for this environment" — which reads as a rollout gap
// rather than a typo in the name.
func TestResolveBinding_UnknownAgentIsDefinitionNotFound(t *testing.T) {
	s := newV1Alpha2TestStore(t)
	ctx := context.Background()

	_, err := s.ResolveBinding(ctx, "no-such-agent", EnvironmentProduction)
	if !errors.Is(err, ErrDefinitionNotFound) {
		t.Fatalf("unknown agent: expected ErrDefinitionNotFound, got %v", err)
	}

	// A declared agent with no binding keeps the other 404.
	if _, err := s.CreateDefinition(ctx, "issue-investigator", "", ""); err != nil {
		t.Fatalf("create definition: %v", err)
	}
	_, err = s.ResolveBinding(ctx, "issue-investigator", EnvironmentProduction)
	if !errors.Is(err, ErrBindingNotFound) {
		t.Fatalf("declared agent, no binding: expected ErrBindingNotFound, got %v", err)
	}
}

// TestPublishDefinitionVersion_RejectsANonObjectSpecBeforeTheDatabase pins
// the store-side half of the spec check. The handler validated it, so the
// rule lived in the caller rather than in the thing it constrains, and a
// non-HTTP caller wrote a scalar into a column the contract says is an
// object.
func TestPublishDefinitionVersion_RejectsANonObjectSpecBeforeTheDatabase(t *testing.T) {
	s := &Store{}
	for _, spec := range []string{`[1,2]`, `42`, `"text"`, `null`, `{`, ``} {
		d := newDefinitionVersion("issue-investigator", "1.0.0", ">=1.0.0 <2.0.0")
		d.SpecJSON = spec
		if _, err := s.PublishDefinitionVersion(context.Background(), d); !errors.Is(err, ErrInvalidSpec) {
			t.Errorf("spec %q: expected ErrInvalidSpec, got %v", spec, err)
		}
	}
}

// TestCreateBinding_DefaultsBindingSource pins the default the docs state
// and only the HTTP handler applied: an omitted binding_source reached the
// column as an empty string, which every reader of the resolve envelope then
// saw instead of "registry".
func TestCreateBinding_DefaultsBindingSource(t *testing.T) {
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
		Actor: "tester", // BindingSource deliberately omitted
	})
	if err != nil {
		t.Fatalf("create binding: %v", err)
	}
	if binding.BindingSource != BindingSourceRegistry {
		t.Fatalf("expected binding_source %q, got %q", BindingSourceRegistry, binding.BindingSource)
	}
}
