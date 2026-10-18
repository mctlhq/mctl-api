# ZITADEL identity hook (customers org)

mctl-api serves three ZITADEL Actions v2 `restCall` targets that make the
`customers` organization a GitHub-only, self-service sign-up org (mctl-web
onboarding plan, B1). Payload shapes and failure semantics were checked
against the ZITADEL **v4.19.2** source. The proto fields the hook writes:
`RetrieveIdentityProviderIntentResponse` oneof `user_action` with
`create_user` (6) and `update_user` (7), the deprecated `add_human_user` (4)
and `update_human_user` (5) being cleared; `CreateUserRequest` top-level
`metadata` (6; the deprecated `human.metadata` is not set, setting both fails
validation); `UpdateUserRequest` top-level `metadata` (5). Login V2
(`idp-intent.ts`) prefers `create_user`/`update_user` when present.

The hook is **inert until configured**: with `ZITADEL_HOOK_CUSTOMERS_ORG_ID`
unset, or any required key missing, the three routes answer `503` and nothing
in ZITADEL calls them until the targets and executions exist
(mctl-gitops `zitadel-iac`).

## Endpoints

All three are unauthenticated routes verified by `ZITADEL-Signature`
(`t=<unix>,v1=<hex>`, HMAC-SHA256 over `"<unix>." + body`). Each target has
its own key; a request older or newer than 300 s, unsigned, or signed with
another target's key is `401`. Bodies over 1 MiB are `413`.

| Path | ZITADEL execution | Target type |
|---|---|---|
| `POST /api/v1/webhooks/zitadel/intent` | response, method `/zitadel.user.v2.UserService/RetrieveIdentityProviderIntent` | `restCall`, `interruptOnError: true` |
| `POST /api/v1/webhooks/zitadel/create-user` | request, every method in the inventory below | `restCall`, `interruptOnError: true` |
| `POST /api/v1/webhooks/zitadel/token-claims` | functions `preuserinfo` and `preaccesstoken` | `restCall`, `interruptOnError: false` |

The intent and create-user targets must interrupt: with `false` ZITADEL
ignores their refusals and the gate is open. The token target must **not**
interrupt (B0 item 5): functions are instance-wide, so an interrupting
failure would block admin tokens too and burn refresh tokens. A failing token
hook therefore yields tokens without `mctl:*` claims, and relying parties
treat a missing `mctl:github_id` as a refusal.

**Hard constraint: the GitHub IdP is an org IdP of customers**
(`zitadel_org_idp_github` on the customers org), never instance-level and
never added to another org's login policy. The update path writes a verified
email onto the `userId` ZITADEL resolved for the GitHub link without checking
its org; that is safe only because every user linked to this IdP was created
in customers through the create gate (the link methods are gated as well, see
below). Changing the IdP's scope breaks that invariant and must not be done
without an `UpdateUser` gate.

ZITADEL's default `HTTPClient.DenyList` blocks private ranges, so the targets
point at the public hostname (`https://api.mctl.ai/...`), not the in-cluster
Service.

### Answers

- **Refusal**: `200` with `{"forwardedStatusCode": 4xx, "forwardedErrorMessage": "..."}`.
  ZITADEL turns it into a user-facing error (`EXEC-reUaUZCzCp`).
- **Failure** (cannot decide: GitHub or gitops unreadable, unparsable
  payload): `503`, which ZITADEL turns into `Errors.Execution.Failed`.
  Both block the call.
- **Pass-through**: `200` with an empty body, which leaves the message
  unchanged. The token target answers `{}` instead.

## Intent (`/intent`)

Runs on the response of `RetrieveIdentityProviderIntent`, which Login V2
reads to decide whether to create or update the user.

- Any IdP other than `ZITADEL_HOOK_GITHUB_IDP_ID` passes through untouched.
- The GitHub id must be numeric and the login a valid GitHub login.
  `rawInformation` (GitHub's `/user` body) must carry `type` = `User`, so
  organizations and bots are refused, an `id` equal to the intent's user id,
  and a `login` equal to the intent's user name (case-insensitive). A missing
  field is a refusal, not a pass.
- An unparsable `userId` is `503`.
- **New user, GitHub id not on the creation allowlist** → refused with `403`
  (`intent_customer_create_not_allowed:<github id>`) before anything else is
  read. See "Creation allowlist" below.
- **New user, reserved login** → refused with `403` before GitHub is called.
  Tenant data that cannot be read → `503`.
- `GET https://api.github.com/user/emails` with the intent's access token
  (the OAuth App needs the `user:email` scope). Only the **primary and
  verified** address is used; the public profile email is ignored. A failed
  read is `503` for a new user; an existing user signs in without an email
  change, so a GitHub outage does not lock customers out.
- Any user action ZITADEL proposed (`addHumanUser`, `updateHumanUser`,
  `createUser`, `updateUser`) is removed. The hook alone sets one.
- **Existing user** (`userId` set): sets `updateUser` with the profile (name,
  falling back to the login), the verified email if there is one (otherwise
  the stored address is kept, also when GitHub could not be read), and
  `github_login` metadata. It never changes
  the username or `github_id`.
- **New user**:
  - No primary verified email → refused with `412`.
  - Otherwise sets `createUser`:
    - `organizationId` = customers, set explicitly;
    - `username` = `<lowercase login>@mctl.ai`;
    - `human.profile` {givenName = name or login, familyName `-`, displayName};
    - `human.email` {verified};
    - exactly one `human.idpLinks` entry;
    - metadata `github_id` and `github_login`.

### Reserved logins

A login is reserved **at creation** when it matches, case-insensitively:

1. `ADMIN_USERS` (always included);
2. `ZITADEL_HOOK_RESERVED_LOGINS` (static extras, such as service logins);
3. a tenant name in the gitops checkout;
4. any tenant or team member `userId` in the gitops checkout.

Tenant data is read with `gitops.Reader.ListTenantsStrict`. A member recorded
with only a `principalId` (no `userId`) makes the reservation undecidable, so
it is `503` as well; every member in gitops carries a `userId` today, and the
api#377 migration must keep it until this check resolves principals. A checkout that
never synced, is older than 10 minutes, is missing, empty, or holds a tenant
that does not parse is an error (`503`), never an empty list.

Sources 3 and 4 apply only at creation. A customer who later becomes a
tenant member under their own login must not lock themselves out.

### Creation allowlist

Until the public cutover is decided, only listed GitHub accounts may create a
**new** customers account. `ZITADEL_HOOK_CUSTOMER_CREATE_GITHUB_IDS` is a CSV
of GitHub **numeric** ids (never logins: a login can be renamed and reused).

- Unset or empty: nobody can create a customers account. Creation is closed
  by default, so a hook deployed without the value refuses every new account
  rather than opening sign-up.
- Exactly `*`: anyone may create one (the public cutover). `*` mixed with ids
  is malformed.
- Anything else malformed refuses the mctl-api boot. It does not just switch
  the hook off, because that would also stop existing customers from signing
  in.

It is enforced twice, on the GitHub id: in `/intent` before the account is
proposed, and in the create gate (rule 9 below) on the link's user id. The
refusal is `403` with "New MCTL accounts are by invitation only for now."
The reason logged is `intent_customer_create_not_allowed:<github id>` or
`gate_customer_create_not_allowed:<github id>`. It carries the id, so a
refused person can be added, and never the email.

The list only gates creation. An existing customers account (`/intent` with a
`userId`) signs in and is updated as before, token claims are unchanged, and
users of other organizations are not affected. To invite someone, add their
GitHub id (`gh api users/<login> --jq .id`) and roll mctl-api. The env var is
read at start.

## Create gate (`/create-user`)

### Method inventory (v4.19.2)

| Method | Gate behaviour |
|---|---|
| `/zitadel.user.v2.UserService/CreateUser` | full customers rules (below) |
| `/zitadel.user.v2.UserService/AddHumanUser` | refused if it touches customers |
| `/zitadel.user.v2beta.UserService/AddHumanUser` | refused if it touches customers |
| `/zitadel.resources.user.v3alpha.ZITADELUsers/CreateUser` | refused if it touches customers |
| `/zitadel.management.v1.ManagementService/AddHumanUser` | refused if it touches customers |
| `/zitadel.management.v1.ManagementService/ImportHumanUser` | refused if it touches customers |
| `/zitadel.management.v1.ManagementService/AddMachineUser` | refused if it touches customers |
| `/zitadel.admin.v1.AdminService/ImportData` | refused if it touches customers |
| `/zitadel.user.v2.UserService/AddIDPLink` | refused if it touches customers |
| `/zitadel.user.v2beta.UserService/AddIDPLink` | refused if it touches customers |
| `/zitadel.resources.user.v3alpha.ZITADELUsers/AddIDPAuthenticator` | refused if it touches customers |
| `/zitadel.management.v1.ManagementService/SetUserMetadata` | identity metadata rules (below) |
| `/zitadel.management.v1.ManagementService/BulkSetUserMetadata` | identity metadata rules (below) |
| `/zitadel.user.v2.UserService/SetUserMetadata` | identity metadata rules (below) |
| `/zitadel.user.v2.UserService/UpdateUser` | identity metadata rules (below) |
| any other method routed to this target | refused (`gate_unknown_method`) |

Not gated, because they only create users in a **new** organization:

- `ManagementService/AddOrg`
- `AdminService/SetUpOrg`
- `org.v2` and `org.v2beta` `OrganizationService/AddOrganization`

The link methods do not create users, but a GitHub link added to an existing
user lets that GitHub account sign in as the user. With them gated, the
invariant is: every user linked to the customers GitHub IdP was created in
customers through this gate. Management v1 has no add-link RPC in v4.19.2.

### Identity metadata after creation

`github_id` and `github_login` are what the token claims carry, so writes of
them after creation are gated too (v2beta and v3alpha have no user metadata
RPC in v4.19.2). Keys are matched as raw text in the request:

- `github_id` is refused in every org. Only the create path writes it, and
  the hook cannot tell from a user id which org the user is in.
- `github_login` is refused when the request touches customers, unless the
  caller is the Login V2 service user, which syncs the login the hook set on
  `/intent`. It is allowed elsewhere because `zitadel-iac` writes it for
  admin and tenant users (`github-login.tf`).
- Any other key passes.

A request that names neither the customers org nor a customers context can
still rewrite a customer's `github_login` by user id alone. Relying parties
therefore authorize on `mctl:github_id` only; `mctl:github_login` is a
display value.

SCIM (`/scim/v2/...`) is plain HTTP, not gRPC, so executions do not cover it.
It is the one exception to the invariant and must stay unused for customers.

"Touches customers" is deliberately coarse. A request touches customers if
any of these hold:

- the call's context org is customers;
- the customers org ID or the GitHub IdP ID appears anywhere in the request;
- it carries any `orgDomain`/`org_domain` field, whatever the value
  (customers also has its generated `<org>.<instance domain>` domain, and the
  hook cannot resolve a domain to an organization);
- the request does not parse.

A false positive refuses an admin call; it can never let a user in.

### `CreateUser` rules

A request that parses as neither `human` nor `machine` (an empty request, a
renamed field, another spelling) is refused: passing requires positive
evidence. A request is in scope when its `organizationId` is customers (or is
empty and the context org is customers), when it carries any GitHub IdP
link, or when the customers org ID or GitHub IdP ID appears anywhere in it.
Everything else passes through. In scope, all of these must hold:

1. `organizationId` is explicitly customers. A GitHub link into any other org
   is refused, as is an org taken only from the context.
2. The caller (`userID`) is `ZITADEL_HOOK_LOGIN_CLIENT_USER_ID`, the Login V2
   service user. When Login V2 authenticates as a System API user, its id is
   the System API user's name (`login-client` in mctl's deployment). A
   refusal logs the caller it saw (`gate_caller_not_login_client:<id>`).
3. The user is human, not a machine.
4. There is no password, hashed password or TOTP secret.
5. There is exactly one IdP link, and it is to the GitHub IdP, with a numeric
   id and a valid login.
6. Metadata `github_id` equals the link's user id and `github_login` equals
   its login. The same key given twice with different values is refused.
7. The email is verified.
8. `username` is `<lowercase login>@mctl.ai`.
9. The link's GitHub id is on the creation allowlist (as above).
10. The login is not reserved (as above).

Rules 1–10 are exactly what `/intent` produces, so a hook-shaped request passes
its own gate. A test pins this.

## Token claims (`/token-claims`)

For a user in customers and a client id in `ZITADEL_HOOK_CLAIM_CLIENT_IDS`,
the hook appends `mctl:org=customers`, `mctl:idp=github`, `mctl:github_id` and
`mctl:github_login`, read from user metadata.

It appends `mctl:refused` instead in two cases:

- metadata `github_id` or `github_login` is missing or invalid →
  `mctl:refused=no_github_identity`;
- the login is in the static reserved list (for example, a customer renamed
  their GitHub account to an admin login) → `mctl:refused=login_reserved`.

Relying parties (mctl-web, and later C0) must refuse any token that carries
`mctl:refused`, or that lacks `mctl:github_id`, and must key identity on
`mctl:github_id`, never on `mctl:github_login`. Other orgs and clients get
`{}`, with no claims.

## Configuration

| Env var | Required | Meaning |
|---|---|---|
| `ZITADEL_HOOK_CUSTOMERS_ORG_ID` | yes (unset = hook off) | customers org ID |
| `ZITADEL_HOOK_GITHUB_IDP_ID` | yes | customers GitHub IdP ID; also the IdP the OAuth chooser's customer "Sign in with GitHub" sends ZITADEL to (`docs/principals.md`). Must be digits: never offered otherwise, and the boot is refused where that entry can be wired (not under `MCTL_FEDERATION_DISABLED`) |
| `ZITADEL_HOOK_LOGIN_CLIENT_USER_ID` | yes | Login V2 service user ID (the only allowed `CreateUser` caller in customers) |
| `ZITADEL_HOOK_CLAIM_CLIENT_IDS` | yes | CSV of OIDC client IDs that get `mctl:*` claims (`mctl-web`, `mctl-web-dev`) |
| `ZITADEL_HOOK_USERNAME_DOMAIN` | no, default `mctl.ai` | username suffix (`<login>@<domain>`) only; org domains are not compared |
| `ZITADEL_HOOK_RESERVED_LOGINS` | no | CSV of extra reserved logins; `ADMIN_USERS` is always added |
| `ZITADEL_HOOK_CUSTOMER_CREATE_GITHUB_IDS` | no (unset = nobody) | CSV of GitHub numeric ids that may create a new customers account, or exactly `*` for anyone. A malformed value refuses boot |
| `ZITADEL_HOOK_INTENT_SIGNING_KEYS` | yes, in practice | CSV; signing key(s) of the intent target |
| `ZITADEL_HOOK_CREATE_SIGNING_KEYS` | yes, in practice | CSV; signing key(s) of the create-user target |
| `ZITADEL_HOOK_TOKEN_SIGNING_KEYS` | yes, in practice | CSV; signing key(s) of the token target |

A target with no signing key configured rejects every call (`401`). Listing
two keys allows rotation without downtime.

## Operational notes

- Routing the metadata methods to the gate means an mctl-api outage also
  blocks `zitadel-iac`'s `github_login` metadata writes and every
  `UpdateUser`, including profile edits, in every org.
- An mctl-api outage, or a stale gitops checkout, blocks every **v2
  `CreateUser`** routed to the gate: Login V2 sign-ups in every org, and
  `zitadel-iac` user resources; the other gated methods fail the same way.
  The break-glass path is deleting the request execution in ZITADEL, which
  opens the gate, so it is an incident action, not maintenance.
- Changing `interruptOnError` on an existing target is a silent no-op (B0
  finding), so a change must replace the target.
