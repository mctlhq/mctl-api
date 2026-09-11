# Agent platform registry (v1alpha2)

This document is the consumer contract for the v1alpha2 layer of the agent
registry: immutable `AgentDefinition` versions, immutable `ExecutionProfile`
versions, and the append-only `ReleaseBinding` ledger that pairs them per
`(agent, environment)`. See ADR 007 for the three-layer model this
implements the third layer of, and `design.md` under
`platform-gitops/agents-state/mctl-api/proposals/issue-283-feat-agent-platform-publish-and-resolve/`
for the full design record this document was frozen alongside.

It exists so `mctl-agents/orchestrator/resolver.py` can implement
`bindingSource: registry` without reverse-engineering the store, and so a
`mctl-gitops` reviewer knows exactly what a merged `ReleaseBindingIntent`
should cause mctl-api to do.

This is **additive**: every v1 route (`POST /agents/{name}/versions`,
`POST /agents/{name}/releases`, `GET /agents/{name}/resolve`), the
`agent_versions` / `agent_releases` tables, and the six original MCP tools
(`mctl_create_agent`, `mctl_publish_agent_version`, `mctl_list_agent_versions`,
`mctl_promote_agent`, `mctl_rollback_agent`, `mctl_list_agent_executions`)
are unchanged. `mctl_resolve_agent` gained an optional `api_version`
argument; every other v1 tool argument, request shape and response shape is
untouched.

## Data model

- **`AgentDefinition`** (`agent_definitions`, unchanged from v1): one row
  per agent name. Still the parent both the v1 `agent_versions` and the new
  `agent_definition_versions` hang off of.
- **`DefinitionVersion`** (`agent_definition_versions`): an immutable,
  published version of one agent's v1alpha2 definition. Carries the full
  spec as JSON, a `SourceManifest` (repo/path/gitSha/contentHash), an
  `owner`, a declared `profileRange` (the compatibility range a bound
  profile version must satisfy — see "Compatibility ranges" below), and a
  `lifecycle`.
- **`ProfileVersion`** (`agent_profile_versions`): an immutable, published
  version of one `ExecutionProfile`. Profile names are a **global key
  space** — not namespaced per agent — because ADR 007 and the fixtures
  under `platform-gitops/agent-platform/` share profiles like
  `standard-investigate` across multiple agents. `(profile, version)` is
  the unique key.
- **`ReleaseBinding`** (`agent_release_bindings`): one append-only revision
  per `(agent, environment)`, pairing an exact `definitionVersion` with an
  exact `profileVersion`. There is **no `active` column anywhere**. The
  active binding for a pair is always
  `ORDER BY revision DESC LIMIT 1` — a derived fact, never a stored one. A
  rollback is a new revision whose `rollbackOf` points at the `id` of the
  restored row.

Every required policy-ceiling field an `ExecutionProfile` spec must carry is
named by `agentregistry.RequiredProfilePolicyFields` — today
`maxTokens`, `maxToolCalls`, `timeoutSeconds`. Publishing a profile version
missing any of them fails with `missing_policy_fields` naming every missing
field.

## Compatibility ranges

A `DefinitionVersion.profileRange` and a `ProfileVersion.version` are both
evaluated by `internal/agentregistry/semver.go`, a small evaluator over a
deliberately narrow grammar — **this is not a general semver library**:

- Versions: strict `MAJOR.MINOR.PATCH`. No `v` prefix, no pre-release or
  build metadata, no partial versions (`1.2` or `1.x` are rejected).
- Ranges: one or more comparator clauses joined by whitespace or commas,
  where **every** clause must be satisfied (an AND, never an OR):
  - `>=`, `>`, `<=`, `<`, `=` — standard numeric comparison.
  - `^MAJOR.MINOR.PATCH` — caret: pins the leftmost nonzero component.
    `^1.2.3` allows `>=1.2.3 <2.0.0`; `^0.2.3` allows `>=0.2.3 <0.3.0`
    (a `0.x` major is treated as unstable, so the minor is pinned instead).
  - `~MAJOR.MINOR.PATCH` — tilde: allows patch bumps only, i.e.
    `~1.2.3` means `>=1.2.3 <1.3.0`.
- Anything outside this grammar — `latest`, `1.x`, a bare version with no
  comparator, `!=`, boolean operators — is rejected with `invalid_range` at
  **publish** time, never accepted and silently mis-evaluated at bind time.
  A range that cannot be parsed must never reach a compatibility check,
  where failing open would be the dangerous outcome.

If `mctl-gitops`'s own `scripts/validate-agent-platform.py` (a follow-up PR,
not part of this change) implements a second evaluator for the same
grammar, keep it byte-for-byte aligned with the table above — two
implementations of one grammar drifting apart is the primary risk this
design accepted; `internal/agentregistry/semver_test.go`'s table-driven
cases are the ones to port.

## REST surface

All routes below require an authenticated admin (`requireAgentRegistryAdmin`
— 503 if the registry isn't configured, 401 unauthenticated, 403
non-admin), same as every v1 agent-registry route.

```
GET    /api/v1/agents                                        -> catalog summary, every agent
GET    /api/v1/agents/{name}                                 -> one agent's full catalog entry

POST   /api/v1/agents/{name}/definition-versions              -> publish a DefinitionVersion
GET    /api/v1/agents/{name}/definition-versions              -> list DefinitionVersions, newest first
POST   /api/v1/agents/{name}/definition-versions/{version}/lifecycle
                                                               -> transition lifecycle

POST   /api/v1/agent-profiles/{profile}/versions               -> publish a ProfileVersion
GET    /api/v1/agent-profiles/{profile}/versions               -> list ProfileVersions, newest first
POST   /api/v1/agent-profiles/{profile}/versions/{version}/lifecycle
                                                               -> transition lifecycle

POST   /api/v1/agents/{name}/bindings                          -> append a new ReleaseBinding revision
GET    /api/v1/agents/{name}/bindings?environment=            -> full revision history for the pair
GET    /api/v1/agents/{name}/bindings/resolve                  -> resolve (see below)
GET    /api/v1/agents/{name}/bindings/{revision}?environment=  -> one exact revision
POST   /api/v1/agents/{name}/bindings/rollback                 -> append a revision restoring a prior one
```

`GET /api/v1/agents/{name}` is a 2-segment route, same segment count as the
existing static `GET /api/v1/agents/executions`. chi's radix tree prefers
the static match, so `/agents/executions` keeps reaching
`ListAgentExecutions` — `internal/api/router_test.go`'s
`TestAgentsExecutionsStaticRouteBeatsDynamicGetAgent` pins this. The same
precedence applies to `bindings/resolve` and `bindings/rollback` (static)
over `bindings/{revision}` (dynamic).

### Publishing a definition version

```
POST /api/v1/agents/{name}/definition-versions
{
  "version": "1.4.0",
  "spec": "{ ... full v1alpha2 AgentDefinition spec ... }",
  "owner": "mctl-agents",
  "source_manifest": {
    "repo": "mctlhq/mctl-agents",
    "path": "agents/_manifests/issue-investigator/agent.yaml",
    "git_sha": "<commit sha>",
    "content_hash": "<sha256 of spec>"
  },
  "profile_range": ">=2.0.0 <3.0.0"
}
```

Required: `version`, `spec`, `owner`, `source_manifest.git_sha`,
`source_manifest.content_hash`, `profile_range` (must parse under the
grammar above). `(agent, version)` is a once-only key — republishing the
same pair is a 409.

### Publishing a profile version

```
POST /api/v1/agent-profiles/{profile}/versions
{
  "version": "2.1.0",
  "spec": "{ \"maxTokens\": 100000, \"maxToolCalls\": 50, \"timeoutSeconds\": 600, ... }",
  "owner": "mctl-agents",
  "source_manifest": { "repo": "...", "path": "...", "git_sha": "...", "content_hash": "..." }
}
```

Same required-field rules, plus every field in
`RequiredProfilePolicyFields` must be present in `spec`'s top level.

### Lifecycle transitions

```
POST /api/v1/agents/{name}/definition-versions/{version}/lifecycle
POST /api/v1/agent-profiles/{profile}/versions/{version}/lifecycle
{ "lifecycle": "deprecated" | "disabled", "reason": "..." }
```

Only `published -> deprecated`, `published -> disabled` and
`deprecated -> disabled` are valid; anything else (including a no-op
`published -> published`) is `invalid_lifecycle_transition` (409). The
immutable `spec` and provenance columns never change — only `lifecycle`,
`lifecycle_reason`, `lifecycle_at`, `lifecycle_by`.

### Creating a binding

```
POST /api/v1/agents/{name}/bindings
{
  "environment": "shadow",
  "definition_version": "1.4.0",
  "profile": "standard-investigate",
  "profile_version": "2.1.0",
  "binding_source": "registry",
  "intent": { "repo": "mctlhq/platform-gitops", "path": "agent-platform/...", "git_sha": "<merge sha>" },
  "reason": "..."
}
```

`binding_source` defaults to `"registry"` if omitted. `"compatibility-fixture"`
is always rejected (`fixture_not_promotable`, 422) — fixture intents are
never promotable by design; `"registry"` is the promotable source this
endpoint exists for. `intent` is optional and is how a binding created from
a gitops merge records its provenance (see "GitOps reconciliation" below).

This never overwrites: every call appends a new revision, monotonic per
`(agent, environment)`, computed as `MAX(revision) + 1` under the same
per-pair Postgres advisory lock the v1 `promote`/`Rollback` path already
uses (`pg_advisory_xact_lock(hashtext(agent + "/" + environment))`), so
concurrent binds cannot duplicate or skip a revision number.

### Resolving

```
GET /api/v1/agents/{name}/bindings/resolve?environment=shadow
GET /api/v1/agents/{name}/bindings/resolve?definition_version=1.4.0&profile=standard-investigate[&profile_version=2.1.0]
```

Exactly one of the two selector forms must be given — `environment` alone,
or `definition_version` + `profile` together (`profile` is required
alongside `definition_version`: profile versions are a global key space,
so a bare version number is not resolvable to one profile family on its
own). Giving both forms, or neither, is a 400.

- **`environment` form**: returns the active binding for `(agent,
  environment)` — the highest revision. 404 (`ErrBindingNotFound`) if no
  binding has ever been created for the pair; a distinct 404
  (`ErrDefinitionNotFound`, from `GET /agents/{name}`) if the agent itself
  is unknown.
- **Explicit-pin form**: returns the same envelope for the named
  `definition_version` + `profile` pair without consulting any
  environment or any binding row. `profile_version` is optional: if
  omitted, the highest published (non-deprecated, non-disabled) version of
  `profile` that satisfies the definition's declared `profileRange` is
  used. If no such version exists, `version_not_found` (404).

Both forms return the same envelope:

```json
{
  "apiVersion": "agents.mctl.ai/v1alpha2",
  "agent": "issue-investigator",
  "environment": "shadow",
  "revision": 3,
  "definition": {
    "version": "1.4.0",
    "lifecycle": "published",
    "owner": "mctl-agents",
    "sourceManifest": { "repo": "...", "path": "...", "gitSha": "...", "contentHash": "..." },
    "spec": "{ ... }"
  },
  "profile": {
    "name": "standard-investigate",
    "version": "2.1.0",
    "lifecycle": "published",
    "sourceManifest": { "repo": "...", "path": "...", "gitSha": "...", "contentHash": "..." },
    "spec": "{ ... }"
  },
  "compatibility": { "range": ">=2.0.0 <3.0.0", "satisfied": true },
  "bindingSource": "registry",
  "intent": { "repo": "...", "path": "...", "gitSha": "..." },
  "rollbackOf": null,
  "createdAt": "2026-09-11T00:00:00Z",
  "createdBy": "mashkovd"
}
```

`environment`, `revision`, `bindingSource`, `intent`, `rollbackOf`,
`createdAt`, `createdBy` are only meaningful for the `environment` form —
the explicit-pin form omits them (`environment`/`revision` absent,
`bindingSource` empty, `rollbackOf` null).

**What `orchestrator/resolver.py` copies into the `ExecutionPlan`:**
`agent`, `environment`, `revision`, `definition.version`, `profile.name`,
`profile.version`, `definition.sourceManifest.gitSha`. Those seven fields
are the frozen contract; everything else in the envelope is informational.

### Rolling back

```
POST /api/v1/agents/{name}/bindings/rollback
{ "environment": "shadow", "revision": 1, "reason": "bad prompt edit" }
```

Appends a new revision that copies revision `1`'s exact definition/profile
pair and sets `rollbackOf` to that revision's `id`. The restored pair's
lifecycle and compatibility are **re-validated inside the same
transaction**: if either version has since become `disabled`, the rollback
is rejected with `version_disabled` (422) rather than silently restoring a
now-bad pair. 404 if `revision` does not belong to that
`(agent, environment)` pair.

### Error codes

`writeErrorCode` (`internal/api/handlers_read.go`) emits
`{"error": "...", "code": "...", "details": {...}}` for every v1alpha2
rejection below (`details` is currently always omitted — the message names
the offending field/version). `writeError`'s plain `{"error": "..."}` shape
is untouched and still used for the v1 routes and for a few generic
v1alpha2 rejections (unknown agent, version conflict, invalid environment,
binding not found) that predate this error-code scheme.

| HTTP | `code` | When |
| --- | --- | --- |
| 400 | `invalid_range` | `profile_range` does not parse under the grammar above |
| 400 | `missing_policy_fields` | a profile spec is missing a required policy-ceiling field |
| 404 | `version_not_found` | a named definition or profile version does not exist |
| 409 | `invalid_lifecycle_transition` | the requested lifecycle change is not `published->deprecated`, `published->disabled` or `deprecated->disabled` |
| 422 | `incompatible_profile` | the named profile version does not satisfy the definition's declared range |
| 422 | `version_deprecated` | either named version is `deprecated` |
| 422 | `version_disabled` | either named version is `disabled` |
| 422 | `fixture_not_promotable` | `binding_source: compatibility-fixture` was used on a bind/rollback |

## MCP tools

Seven new tools, all admin-only, registered next to the six v1 tools in
`internal/mcp/server.go`:

| Tool | REST route | Confirm gate |
| --- | --- | --- |
| `mctl_publish_agent_definition_version` | `POST .../definition-versions` | no |
| `mctl_publish_agent_profile_version` | `POST .../versions` (profile) | no |
| `mctl_set_agent_version_lifecycle` | `POST .../lifecycle` | yes |
| `mctl_bind_agent_release` | `POST .../bindings` | yes |
| `mctl_rollback_agent_binding` | `POST .../bindings/rollback` | yes |
| `mctl_list_agents` | `GET /agents` | no (read-only) |
| `mctl_get_agent` | `GET /agents/{name}` | no (read-only) |

`mctl_resolve_agent` is **extended**, not duplicated: an optional
`api_version` argument (`v1` default, or `v1alpha2`) selects between the
v1 `/resolve?environment=` path and the v1alpha2 `/bindings/resolve` path;
`definition_version` / `profile` / `profile_version` are the v1alpha2
explicit-pin arguments. A call passing only `agent_name` + `environment`
(the pre-existing shape) is byte-identical to before this argument existed.

All seven new tools default to `"enabled": false` in
`docs/portal-allowlist.json`, matching `mctl_create_agent` and the rest of
the v1 registry family — the portal does not expose any registry mutation
or catalog-read tool today.

## Execution identity

`POST /api/v1/agents/executions` (`RecordAgentExecution`) gained four
optional fields: `definition_version`, `profile`, `profile_version`,
`binding_revision`. All default to empty/`NULL`; an existing
`orchestrator/temporal/activities/state.py` caller sending only the v1
fields is unaffected. `GET /api/v1/agents/executions` (`ListAgentExecutions`)
returns them. This is how a DevLoopWorkflow step that resolved through a
`ReleaseBinding` records the exact pair and revision it ran with, alongside
the pre-existing `version`/`image_ref` fields — the trace attributes
themselves are `mctl-agents#196`'s job; mctl-api only accepts, stores and
returns the tuple.

## GitOps reconciliation contract

**Push, not pull.** `mctl-api` has no gitops write credential and
`internal/gitops/reader.go` is a read-only clone-and-parse path, so the
registry cannot poll `platform-gitops/agent-platform/` for changes. Instead:

1. A `ReleaseBindingIntent` in `platform-gitops/agent-platform/` is
   authored/reviewed as a normal PR.
2. When that PR sets `bindingSource: registry` and `promotable: true` and
   is merged, `mctl-gitops` CI calls:

   ```
   POST /api/v1/agents/{name}/bindings
   {
     "environment": "<intent.environment>",
     "definition_version": "<intent.definitionVersion>",
     "profile": "<intent.profile>",
     "profile_version": "<intent.profileVersion>",
     "binding_source": "registry",
     "intent": {
       "repo": "mctlhq/platform-gitops",
       "path": "<path to the ReleaseBindingIntent file>",
       "git_sha": "<merge commit sha>"
     },
     "reason": "<PR title or number>"
   }
   ```

3. mctl-api is the authority for what is **active** (the derived highest
   revision); gitops review is the **gate** for what gets proposed. The two
   validators cannot drift into disagreeing about promotability because
   mctl-api independently rejects `bindingSource: compatibility-fixture`
   at bind time (`fixture_not_promotable`) — the mirror of the gitops
   validator's non-promotable rule for fixture intents.
4. `scripts/validate-agent-platform.py` and the `platform-gitops` README
   change that make `bindingSource: registry` + `promotable: true` the
   documented supported path are a **follow-up PR in mctl-gitops**, not
   part of this change. This document is what that PR should implement
   against.

## Seeding `issue-investigator`

`scripts/seed-agent-platform.sh` publishes one definition version and one
profile version for `issue-investigator` and binds them in `shadow` — not
`production`: the live dev-loop pipeline still resolves `production`
through the v1 `agent_releases` path
(`ISSUE_INVESTIGATOR_RESOLVER_MODE=legacy`), so a `shadow` binding gives
`mctl-agents` something real to resolve against with zero blast radius on
a running pipeline.

## What this change does not do

- No governed mutation operations (`mctl_propose_agent`,
  `mctl_deprecate_agent`) — later phase, depends on `mctl-agents#242`.
- No registry/operations UI in `mctl-portal` — phase 4.
- Does not flip `ISSUE_INVESTIGATOR_RESOLVER_MODE` to `declarative`, or
  migrate `implementer`/`shepherd` onto this layer — separate
  `mctl-agents` issues.
- Does not implement the mctl-gitops-side validator/README change — see
  "GitOps reconciliation contract" above.
- Does not produce the `ExecutionPlan` or trace attributes —
  `mctl-agents#196`'s job; mctl-api only accepts, stores and returns the
  resolved tuple.
- No weighted/canary traffic splitting between two bindings.
