// Copyright 2026 MCTL Authors
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

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/connect"
	"github.com/mctlhq/mctl-api/internal/glovo/wire"
	"github.com/mctlhq/mctl-api/internal/secretscan"
)

// ready sets up alpha with a1 and a2 allowlisted and installed, and beta with b1.
func (e *e2eEnv) readyAlphaBeta() (alphaRev, betaRev int64) {
	e.t.Helper()
	e.members.set("beta", prnOwner, "owner")
	e.allow("alpha", prnA1)
	e.allow("alpha", prnA2)
	e.allow("beta", prnB1)
	return e.installTenant("alpha"), e.installTenant("beta")
}

// T3: isolation. A foreign id and a missing id are the same 404 with the same
// body, on every facade route that takes an id.
func TestGlovoE2EIsolation(t *testing.T) {
	e := newE2E(t, e2eOpts{})
	rev, _ := e.readyAlphaBeta()
	a1, a2, b1 := e.mint(prnA1, "alpha"), e.mint(prnA2, "alpha"), e.mint(prnB1, "beta")
	id := e.connectAs(a1)
	missing := "gcn_01JZZZZZZZZZZZZZZZZZZZZZZZ"

	for _, rt := range [][2]string{
		{http.MethodGet, ""}, {http.MethodPost, "/handoff"}, {http.MethodPost, "/revoke"}, {http.MethodPost, "/reconnect"},
	} {
		var bodies [][]byte
		for _, tc := range []struct{ tok, id string }{{a2, id}, {b1, id}, {a1, missing}} {
			code, raw := e.call(rt[0], facade+"/connections/"+tc.id+rt[1], tc.tok, nil, "Idempotency-Key", e.key())
			if code != http.StatusNotFound {
				t.Fatalf("%s %s: %d %s", rt[0], rt[1], code, raw)
			}
			bodies = append(bodies, raw)
		}
		if !bytes.Equal(bodies[0], bodies[1]) || !bytes.Equal(bodies[0], bodies[2]) {
			t.Fatalf("%s %s: foreign and missing bodies differ: %q %q %q", rt[0], rt[1], bodies[0], bodies[1], bodies[2])
		}
	}
	// a1's connection is untouched by the foreign attempts.
	if code, m := e.callJSON(http.MethodGet, facade+"/connections/"+id, a1, nil); code != http.StatusOK || m["state"] != "pending" {
		t.Fatalf("a1 own connection: %d %v", code, m)
	}
	// The worker check against the wrong revision.
	if code, m := e.check(id, rev+1); code != http.StatusForbidden || errCode(m) != "stale_install" {
		t.Fatalf("wrong revision: %d %v", code, m)
	}
	// a2's context shows only a2's connections.
	if code, m := e.callJSON(http.MethodGet, facade+"/context", a2, nil); code != http.StatusOK || len(m["connections"].([]any)) != 0 {
		t.Fatalf("a2 context: %d %v", code, m)
	}
}

// T4: every ungranted, unselected, stale or forged input fails closed.
func TestGlovoE2EFailClosed(t *testing.T) {
	e := newE2E(t, e2eOpts{})
	rev, _ := e.readyAlphaBeta()
	e.allow("alpha", prnU3)
	e.allow("labs", prnU3)
	e.allow("sys", prnA1)

	refused := func(name, tok string, wantStatus int, wantCode string) {
		t.Helper()
		code, m := e.callJSON(http.MethodGet, facade+"/context", tok, nil)
		if code != wantStatus || (wantCode != "" && errCode(m) != wantCode) {
			t.Errorf("%s: %d %v, want %d %s", name, code, m, wantStatus, wantCode)
		}
	}
	refused("token with no grant", e.forge(glovoRes, prnA1, "", ""), http.StatusForbidden, "ambiguous_tenant")
	refused("grant id that does not exist", e.forge(glovoRes, prnA1, "tgr_00000000000000000000000000000000", "alpha"), http.StatusForbidden, "ambiguous_tenant")
	// u3 is eligible in alpha and in labs but selected nothing: no fallback.
	refused("u3 unselected (labs is not a default)", e.forge(glovoRes, prnU3, "", ""), http.StatusForbidden, "ambiguous_tenant")
	refused("wrong audience", e.forge("https://other.example/mcp", prnA1, "", ""), http.StatusUnauthorized, "")
	refused("multi-aud glovo and api", e.forge([]string{glovoRes, "https://api.mctl.ai"}, prnA1, "", ""), http.StatusUnauthorized, "")
	refused("api audience is not a glovo caller", e.forge("https://api.mctl.ai", prnA1, "", ""), http.StatusForbidden, "not_authorized")
	// A team the resolver does not support (system tenant): consent allowed
	// it, the resolver refuses it.
	refused("system tenant", e.mint(prnA1, "sys"), http.StatusForbidden, "scope_unsupported")

	// u3 may select labs explicitly; nothing else picks it. A selected team
	// without a current install is refused at use with no_install.
	if code, m := e.callJSON(http.MethodGet, facade+"/context", e.mint(prnU3, "labs"), nil); code != http.StatusForbidden || errCode(m) != "no_install" {
		t.Errorf("labs without an install: %d %v", code, m)
	}
	if _, err := e.store.Install(context.Background(), "labs", glovo.Actor{PrincipalID: prnOwner, Kind: glovo.ActorOwner}); err != nil {
		t.Fatal(err)
	}
	if code, m := e.callJSON(http.MethodGet, facade+"/context", e.mint(prnU3, "labs"), nil); code != http.StatusOK || m["tenant"] != "labs" {
		t.Errorf("explicit labs: %d %v", code, m)
	}

	// Forged inputs.
	a1 := e.mint(prnA1, "alpha")
	for name, body := range map[string]map[string]any{
		"tenant":           {"schema": "glovo-connection/v1alpha1.ConnectRequest", "tenant": "beta"},
		"owner":            {"schema": "glovo-connection/v1alpha1.ConnectRequest", "owner": prnA2},
		"install_revision": {"schema": "glovo-connection/v1alpha1.ConnectRequest", "install_revision": rev + 5},
		"wrong schema":     {"schema": "glovo-connection/v1alpha1.Connection"},
	} {
		if code, m := e.callJSON(http.MethodPost, facade+"/connections", a1, body, "Idempotency-Key", e.key()); code != http.StatusBadRequest || errCode(m) != "invalid_request" {
			t.Errorf("forged %s: %d %v", name, code, m)
		}
	}
	if code, m := e.callJSON(http.MethodPost, worker+"/check", e2eWorkerTok,
		map[string]any{"schema": "glovo-connection/v1alpha1.WorkerCheckRequest", "connection_id": "gcn_x", "install_revision": 1, "tenant": "beta"}); code != http.StatusBadRequest {
		t.Errorf("forged worker tenant: %d %v", code, m)
	}
	if code, m := e.callJSON(http.MethodGet, facade+"/context", a1, nil, "X-Mctl-Selected-Tenant", "beta", "X-Tenant", "beta"); code != http.StatusOK || m["tenant"] != "alpha" {
		t.Errorf("forged selected-tenant header: %d %v", code, m)
	}

	// Role removed mid-session and allowlist row deleted: refused on the next
	// facade call and the next worker check.
	a2 := e.mint(prnA2, "alpha")
	cid := e.activeConnection(a1, rev)
	cid2 := e.activeConnection(a2, rev)
	if code, m := e.check(cid, rev); code != http.StatusOK || m["allowed"] != true {
		t.Fatalf("before: %d %v", code, m)
	}
	e.members.set("alpha", prnA1, "")
	refused("role removed", a1, http.StatusForbidden, "no_tenant")
	if code, m := e.check(cid, rev); code != http.StatusForbidden || errCode(m) != "no_tenant" {
		t.Errorf("worker check after role removal: %d %v", code, m)
	}
	e.unallow("alpha", prnA2)
	refused("allowlist removed", a2, http.StatusForbidden, "not_in_pilot")
	if code, m := e.check(cid2, rev); code != http.StatusForbidden || errCode(m) != "not_in_pilot" {
		t.Errorf("worker check after allowlist removal: %d %v", code, m)
	}
	// Activation re-derives too.
	e.members.set("alpha", prnA2, "")
	if code, m := e.activate(cid2, rev, "ghr_x"); code != http.StatusForbidden {
		t.Errorf("activate after membership loss: %d %v", code, m)
	}
}

// T5 and T9: audit rows, refusal audit, no leak, and the wire schemas.
func TestGlovoE2EAuditNoLeakAndSchemas(t *testing.T) {
	e := newE2E(t, e2eOpts{})
	rev, _ := e.readyAlphaBeta()
	a1 := e.mint(prnA1, "alpha")

	compile := func(name string) *jsonschema.Schema {
		c := jsonschema.NewCompiler()
		fs := wire.SchemaFS()
		entries, _ := fs.ReadDir("schema")
		for _, en := range entries {
			raw, _ := fs.ReadFile("schema/" + en.Name())
			doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			if err := c.AddResource("wire/"+en.Name(), doc); err != nil {
				t.Fatal(err)
			}
		}
		s, err := c.Compile("wire/" + name + ".json")
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	valid := func(name string, raw []byte) {
		t.Helper()
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("%s: %v: %s", name, err, raw)
		}
		if err := compile(name).Validate(doc); err != nil {
			t.Errorf("%s does not validate: %v\n%s", name, err, raw)
		}
	}
	callRaw := func(want int, name, method, path, tok string, body any, hdr ...string) []byte {
		t.Helper()
		code, raw := e.call(method, path, tok, body, hdr...)
		if code != want {
			t.Fatalf("%s: %d, want %d: %s", name, code, want, raw)
		}
		if name != "" {
			valid(name, raw)
		}
		return raw
	}

	valid("context", callRaw(200, "", http.MethodGet, facade+"/context", a1, nil))
	var conn struct {
		ID string `json:"connection_id"`
	}
	raw := callRaw(201, "connection", http.MethodPost, facade+"/connections", a1, e2eBody(wire.SchemaConnectRequest), "Idempotency-Key", e.key())
	_ = json.Unmarshal(raw, &conn)
	// Replay of the same key.
	key := e.keys[len(e.keys)-1]
	callRaw(200, "connection", http.MethodPost, facade+"/connections", a1, e2eBody(wire.SchemaConnectRequest), "Idempotency-Key", key)
	callRaw(200, "connection", http.MethodGet, facade+"/connections/"+conn.ID, a1, nil)
	ref := e.handoffAs(a1, conn.ID)
	// The handoff response itself.
	hraw := callRaw(200, "handoff", http.MethodPost, facade+"/connections/"+conn.ID+"/handoff", a1, nil)
	var h struct {
		Ref string `json:"handoff_ref"`
	}
	_ = json.Unmarshal(hraw, &h)
	e.refs = append(e.refs, h.Ref)
	_ = ref // superseded by the second reference: the first no longer activates
	if code, _ := e.activate(conn.ID, rev, ref); code != http.StatusNotFound {
		t.Fatalf("an older reference still activates: %d", code)
	}
	raw = callRaw(200, "connection", http.MethodPost, worker+"/connections/"+conn.ID+"/activate", e2eWorkerTok,
		map[string]any{"schema": wire.SchemaWorkerActivate, "install_revision": rev, "handoff_ref": h.Ref})
	callRaw(200, "worker-check-response", http.MethodPost, worker+"/check", e2eWorkerTok,
		map[string]any{"schema": wire.SchemaWorkerCheckReq, "connection_id": conn.ID, "install_revision": rev})
	callRaw(200, "connection", http.MethodPost, facade+"/connections/"+conn.ID+"/revoke", a1, nil)
	// A refusal that names an existing connection is audited; the schema is the
	// glovo.WriteError one.
	valid("error", callRaw(409, "", http.MethodPost, facade+"/connections/"+conn.ID+"/handoff", a1, nil))
	callRaw(200, "installation", http.MethodPut, "/api/v1/glovo/tenants/alpha/installation", "tu:owner", nil)
	callRaw(200, "installation", http.MethodDelete, "/api/v1/glovo/tenants/alpha/installation", "tu:owner", nil)

	// Pre-scope refusals write no audit row.
	before := e.count(`SELECT count(*) FROM glovo.glovo_audit_events`)
	for _, tok := range []string{e.forge(glovoRes, prnA1, "", ""), e.mint(prnA1, "alpha")} {
		_, _ = e.call(http.MethodPost, facade+"/connections", tok, e2eBody(wire.SchemaConnectRequest), "Idempotency-Key", e.key())
	}
	e.unallow("alpha", prnA1)
	_, _ = e.call(http.MethodGet, facade+"/context", a1, nil)
	// The two connects above: the first is ambiguous_tenant, the second is no_install
	// (alpha was uninstalled): neither writes a row. The unallowed one is not_in_pilot.
	if after := e.count(`SELECT count(*) FROM glovo.glovo_audit_events`); after != before {
		t.Errorf("pre-scope refusals wrote %d audit rows", after-before)
	}

	// Audit rows of the connection.
	events, err := e.store.ListAudit(context.Background(), "alpha", conn.ID)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, ev := range events {
		names = append(names, ev.Event)
	}
	for _, want := range []string{"connection_connected", "handoff_issued", "connection_pending_provider", "connection_active", "connection_revoked", "refused"} {
		found := false
		for _, n := range names {
			found = found || n == want
		}
		if !found {
			t.Errorf("audit row %q missing: %v", want, names)
		}
	}
	instEvents := e.count(`SELECT count(*) FROM glovo.glovo_audit_events WHERE entity_kind = 'install' AND event IN ('install_created','install_reinstalled','install_revoked')`)
	if instEvents < 3 {
		t.Errorf("install audit rows: %d", instEvents)
	}

	// No leak: the log, every audit row and every response but the handoff one.
	var rows bytes.Buffer
	r, err := e.pool.Query(context.Background(), `SELECT to_jsonb(a)::text FROM glovo.glovo_audit_events a`)
	if err != nil {
		t.Fatal(err)
	}
	for r.Next() {
		var s string
		_ = r.Scan(&s)
		rows.WriteString(s + "\n")
	}
	r.Close()
	e.respMu.Lock()
	var resp bytes.Buffer
	for _, b := range e.responses {
		resp.Write(b)
		resp.WriteByte('\n')
	}
	e.respMu.Unlock()
	secrets := append(append(append([]string{}, e.minted...), e.keys...), e.refs...)
	secrets = append(secrets, e2eWorkerTok, e2eServiceTk)
	for name, hay := range map[string]string{"slog buffer": e.logs.String(), "audit rows": rows.String(), "responses": resp.String()} {
		if hay == "" {
			t.Errorf("%s is empty: the scan would be vacuous", name)
		}
		for _, s := range secrets {
			if strings.Contains(hay, s) {
				t.Errorf("%s contains a secret value (%d bytes)", name, len(s))
			}
		}
		if hit, ok := secretscan.Scan([]byte(hay)); ok {
			t.Errorf("secretscan found %q in the %s", hit, name)
		}
	}

	// Body contract: unknown field, wrong schema, over 16 KiB.
	big := `{"schema":"` + wire.SchemaConnectRequest + `","pad":"` + strings.Repeat("a", 17<<10) + `"}`
	e.allow("alpha", prnA1)
	e.installTenant("alpha")
	a1 = e.mint(prnA1, "alpha")
	for name, body := range map[string]string{"oversize": big, "unknown field": `{"schema":"` + wire.SchemaConnectRequest + `","x":1}`, "wrong schema": `{"schema":"nope"}`} {
		if code, _ := e.call(http.MethodPost, facade+"/connections", a1, body, "Idempotency-Key", e.key()); code != http.StatusBadRequest {
			t.Errorf("%s: %d", name, code)
		}
	}
}

// T6: lifecycle.
func TestGlovoE2ELifecycle(t *testing.T) {
	e := newE2E(t, e2eOpts{})
	rev, _ := e.readyAlphaBeta()
	a1, a2 := e.mint(prnA1, "alpha"), e.mint(prnA2, "alpha")
	ctx := context.Background()

	// Reinstall revokes live connections atomically; the old revision is stale.
	id := e.activeConnection(a1, rev)
	code, m := e.callJSON(http.MethodPut, "/api/v1/glovo/tenants/alpha/installation", "tu:owner", nil)
	if code != http.StatusOK || int64(m["install_revision"].(float64)) != rev+1 {
		t.Fatalf("reinstall: %d %v", code, m)
	}
	rev++
	if code, m := e.check(id, rev-1); code != http.StatusForbidden || errCode(m) != "stale_install" {
		t.Fatalf("old revision: %d %v", code, m)
	}
	if code, m := e.check(id, rev); code != http.StatusForbidden || errCode(m) != "stale_install" {
		t.Fatalf("connection bound to the old revision: %d %v", code, m)
	}
	if v, err := e.store.GetConnectionView(ctx, glovo.Owner{TenantID: "alpha", PrincipalID: prnA1}, id); err != nil || v.State != glovo.Revoked {
		t.Fatalf("reinstall left the connection %v (%v)", v, err)
	}
	if n := e.count(`SELECT count(*) FROM glovo.glovo_connections WHERE tenant_id = 'alpha' AND state IN ('pending_handoff','pending_provider','active') AND install_revision < $1`, rev); n != 0 {
		t.Fatalf("%d live connections on a stale revision", n)
	}

	// Reconnect after a revoked prior: a new gcn_ with supersedes_id; the old
	// one stays terminal.
	code, m = e.callJSON(http.MethodPost, facade+"/connections/"+id+"/reconnect", a1, nil, "Idempotency-Key", e.key())
	if code != http.StatusCreated || m["supersedes_id"] != id || m["connection_id"] == id || m["state"] != "pending" {
		t.Fatalf("reconnect: %d %v", code, m)
	}
	id2 := m["connection_id"].(string)
	if code, m := e.callJSON(http.MethodGet, facade+"/connections/"+id, a1, nil); code != http.StatusOK || m["state"] != "revoked" {
		t.Fatalf("old connection: %d %v", code, m)
	}
	// From a live prior: connection_exists, never a supersede.
	if code, m := e.callJSON(http.MethodPost, facade+"/connections/"+id2+"/reconnect", a1, nil, "Idempotency-Key", e.key()); code != http.StatusConflict || errCode(m) != "connection_exists" {
		t.Fatalf("reconnect from live: %d %v", code, m)
	}
	// From a failed prior, and from an active prior whose expires_at has passed.
	worker := glovo.WithActor(ctx, glovo.Actor{PrincipalID: "worker", Kind: glovo.ActorWorker})
	view, err := e.store.GetConnectionView(ctx, glovo.Owner{TenantID: "alpha", PrincipalID: prnA1}, id2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.Transition(worker, view.Owner, id2, glovo.Failed, view.Version, "provider_failed", nil); err != nil {
		t.Fatal(err)
	}
	if code, m := e.check(id2, rev); code != http.StatusNotFound || errCode(m) != "no_connection" {
		t.Fatalf("failed connection check: %d %v", code, m)
	}
	code, m = e.callJSON(http.MethodPost, facade+"/connections/"+id2+"/reconnect", a1, nil, "Idempotency-Key", e.key())
	if code != http.StatusCreated {
		t.Fatalf("reconnect from failed: %d %v", code, m)
	}
	id3 := m["connection_id"].(string)
	ref := e.handoffAs(a1, id3)
	if code, m := e.activate(id3, rev, ref); code != http.StatusOK {
		t.Fatalf("activate: %d %v", code, m)
	}
	// expires_at passes (database clock): reads and checks answer expired.
	e.adminExec(`UPDATE glovo.glovo_connections SET expires_at = clock_timestamp() - interval '1 minute' WHERE connection_id = $1`, id3)
	if code, m := e.check(id3, rev); code != http.StatusConflict || errCode(m) != "connection_expired" {
		t.Fatalf("check after expiry: %d %v", code, m)
	}
	if code, m := e.callJSON(http.MethodGet, facade+"/connections/"+id3, a1, nil); code != http.StatusOK || m["state"] != "expired" {
		t.Fatalf("read after expiry: %d %v", code, m)
	}
	if code, m := e.callJSON(http.MethodPost, facade+"/connections/"+id3+"/reconnect", a1, nil, "Idempotency-Key", e.key()); code != http.StatusCreated {
		t.Fatalf("reconnect from lapsed active: %d %v", code, m)
	}

	// Worker expire.
	id4 := e.activeConnection(a2, rev)
	if code, m := e.expire(id4); code != http.StatusOK || m["state"] != "expired" {
		t.Fatalf("expire: %d %v", code, m)
	}
	if code, m := e.check(id4, rev); code != http.StatusConflict || errCode(m) != "connection_expired" {
		t.Fatalf("check after expire: %d %v", code, m)
	}
}

// T6 continued: the handoff and activate refusal table.
func TestGlovoE2EHandoffRefusalTable(t *testing.T) {
	e := newE2E(t, e2eOpts{})
	rev, _ := e.readyAlphaBeta()
	a1, a2 := e.mint(prnA1, "alpha"), e.mint(prnA2, "alpha")
	ctx := context.Background()
	workerCtx := glovo.WithActor(ctx, glovo.Actor{PrincipalID: "worker", Kind: glovo.ActorWorker})
	o1 := glovo.Owner{TenantID: "alpha", PrincipalID: prnA1}

	idA1 := e.connectAs(a1)
	refA1 := e.handoffAs(a1, idA1)
	idA2 := e.connectAs(a2)
	refA2 := e.handoffAs(a2, idA2)

	var bodies [][]byte
	notFound := func(name, id string, rev int64, ref string) {
		t.Helper()
		code, raw := e.call(http.MethodPost, worker+"/connections/"+id+"/activate", e2eWorkerTok,
			map[string]any{"schema": wire.SchemaWorkerActivate, "install_revision": rev, "handoff_ref": ref})
		if code != http.StatusNotFound {
			t.Fatalf("%s: %d %s", name, code, raw)
		}
		bodies = append(bodies, raw)
	}
	notFound("wrong reference", idA1, rev, "ghr_"+strings.Repeat("0", 64))
	notFound("foreign reference (a2's)", idA1, rev, refA2)
	notFound("unknown connection", "gcn_01JZZZZZZZZZZZZZZZZZZZZZZZ", rev, refA1)
	e.adminExec(`UPDATE glovo.glovo_handoff_refs SET expires_at = clock_timestamp() - interval '1 second' WHERE connection_id = $1`, idA2)
	notFound("expired reference", idA2, rev, refA2)
	if code, m := e.activate(idA1, rev, refA1); code != http.StatusOK {
		t.Fatalf("activate: %d %v", code, m)
	}
	// idA1 is now active; a consumed reference on a fresh connection of the same owner.
	if code, _ := e.callJSON(http.MethodPost, facade+"/connections/"+idA1+"/revoke", a1, nil); code != http.StatusOK {
		t.Fatal("revoke")
	}
	idA1b := e.connectAs(a1)
	refB := e.handoffAs(a1, idA1b)
	if code, m := e.activate(idA1b, rev, refB); code != http.StatusOK {
		t.Fatalf("activate b: %d %v", code, m)
	}
	notFound("consumed reference of an earlier connection", idA2, rev, refB)
	for i := 1; i < len(bodies); i++ {
		if !bytes.Equal(bodies[0], bodies[i]) {
			t.Fatalf("not_found bodies differ (an oracle): %q vs %q", bodies[0], bodies[i])
		}
	}

	// State table for handoff and activate.
	type tc struct {
		name   string
		setup  func() string // returns the connection id
		status int
		code   string
	}
	freshPending := func() string {
		// a1 has a live connection (idA1b): end it, then start over.
		_, _ = e.store.Revoke(ctx, o1, glovo.Actor{PrincipalID: prnA1, Kind: glovo.ActorUser}, idA1b, "user_revoked")
		return e.connectAs(a1)
	}
	cases := []tc{
		{"pending_provider", func() string {
			id := freshPending()
			v, _ := e.store.GetConnectionView(ctx, o1, id)
			if _, err := e.store.Transition(workerCtx, o1, id, glovo.PendingProvider, v.Version, "", nil); err != nil {
				t.Fatal(err)
			}
			return id
		}, http.StatusConflict, "invalid_transition"},
		{"active", func() string { id := freshPending(); ref := e.handoffAs(a1, id); e.activate(id, rev, ref); return id }, http.StatusConflict, "invalid_transition"},
		{"revoked", func() string {
			id := freshPending()
			_, _ = e.store.Revoke(ctx, o1, glovo.Actor{PrincipalID: prnA1, Kind: glovo.ActorUser}, id, "user_revoked")
			return id
		}, http.StatusConflict, "connection_revoked"},
		{"expired", func() string { id := freshPending(); e.expire(id); return id }, http.StatusConflict, "connection_expired"},
		{"failed", func() string {
			id := freshPending()
			v, _ := e.store.GetConnectionView(ctx, o1, id)
			if _, err := e.store.Transition(workerCtx, o1, id, glovo.Failed, v.Version, "provider_failed", nil); err != nil {
				t.Fatal(err)
			}
			return id
		}, http.StatusNotFound, "no_connection"},
	}
	for _, c := range cases {
		id := c.setup()
		hcode, hm := e.callJSON(http.MethodPost, facade+"/connections/"+id+"/handoff", a1, nil)
		if hcode != c.status || errCode(hm) != c.code {
			t.Errorf("handoff on %s: %d %v, want %d %s", c.name, hcode, hm, c.status, c.code)
		}
		acode, am := e.activate(id, rev, "ghr_"+strings.Repeat("1", 64))
		if acode != c.status || errCode(am) != c.code {
			t.Errorf("activate on %s: %d %v, want %d %s", c.name, acode, am, c.status, c.code)
		}
		// The refusal names an existing connection: it is audited.
		if n := e.count(`SELECT count(*) FROM glovo.glovo_audit_events WHERE entity_id = $1 AND event = 'refused' AND reason_code = $2`, id, c.code); n < 1 {
			t.Errorf("%s: no audit row for the %s refusal", c.name, c.code)
		}
		// Reset: end the live one so the next case can connect.
		_, _ = e.store.Revoke(ctx, o1, glovo.Actor{PrincipalID: prnA1, Kind: glovo.ActorUser}, id, "user_revoked")
	}
}

// T7: idempotency, limits and races.
func TestGlovoE2EIdempotencyAndLimits(t *testing.T) {
	e := newE2E(t, e2eOpts{})
	rev, _ := e.readyAlphaBeta()
	a1, a2 := e.mint(prnA1, "alpha"), e.mint(prnA2, "alpha")
	ctx := context.Background()

	// Missing key: 400.
	if code, m := e.callJSON(http.MethodPost, facade+"/connections", a1, nil); code != http.StatusBadRequest || errCode(m) != "invalid_request" {
		t.Fatalf("missing key: %d %v", code, m)
	}
	// Same key: replay.
	key := e.key()
	code, m := e.callJSON(http.MethodPost, facade+"/connections", a1, nil, "Idempotency-Key", key)
	if code != http.StatusCreated || m["replayed"] != nil {
		t.Fatalf("first: %d %v", code, m)
	}
	id := m["connection_id"].(string)
	code, m = e.callJSON(http.MethodPost, facade+"/connections", a1, nil, "Idempotency-Key", key)
	if code != http.StatusOK || m["replayed"] != true || m["connection_id"] != id {
		t.Fatalf("replay: %d %v", code, m)
	}
	// Same key on another operation (a different request hash): reused.
	if code, m := e.callJSON(http.MethodPost, facade+"/connections/"+id+"/reconnect", a1, nil, "Idempotency-Key", key); code != http.StatusConflict || errCode(m) != "idempotency_key_reused" {
		t.Fatalf("key reuse: %d %v", code, m)
	}

	// The eleventh connect in an hour is 429 (ten succeed, each ended first).
	o1 := glovo.Owner{TenantID: "alpha", PrincipalID: prnA1}
	actor := glovo.Actor{PrincipalID: prnA1, Kind: glovo.ActorUser}
	_, _ = e.store.Revoke(ctx, o1, actor, id, "user_revoked")
	for i := 2; i <= 10; i++ {
		id := e.connectAs(a1)
		_, _ = e.store.Revoke(ctx, o1, actor, id, "user_revoked")
	}
	if code, m := e.callJSON(http.MethodPost, facade+"/connections", a1, nil, "Idempotency-Key", e.key()); code != http.StatusTooManyRequests || errCode(m) != "rate_limited" {
		t.Fatalf("eleventh connect: %d %v", code, m)
	}

	// 50 non-terminal connections per tenant: the 51st by any principal is 429.
	e.allow("alpha", prnU3)
	e.allow("alpha", prnOwner)
	u3, owner := e.mint(prnU3, "alpha"), e.mint(prnOwner, "alpha")
	e.seedLive("alpha", 48, rev)
	for name, tok := range map[string]string{"49th": a2, "50th": u3} {
		if code, m := e.callJSON(http.MethodPost, facade+"/connections", tok, nil, "Idempotency-Key", e.key()); code != http.StatusCreated {
			t.Fatalf("%s: %d %v", name, code, m)
		}
	}
	if code, m := e.callJSON(http.MethodPost, facade+"/connections", owner, nil, "Idempotency-Key", e.key()); code != http.StatusTooManyRequests || errCode(m) != "rate_limited" {
		t.Fatalf("51st: %d %v", code, m)
	}
}

// seedLive creates n live connections for synthetic principals of tenant,
// through the store, with no limits (the way a different replica would).
func (e *e2eEnv) seedLive(tenant string, n int, rev int64) {
	e.t.Helper()
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	for i := 0; i < n; i++ {
		prn := "prn_01J" + strings.Repeat("Z", 21) + string(alphabet[i/32]) + string(alphabet[i%32])
		_, err := e.store.Connect(context.Background(), glovo.ConnectInput{
			Owner: glovo.Owner{TenantID: tenant, PrincipalID: prn}, ExpectedInstallRevision: rev, IdempotencyKey: "seed-" + prn,
			Actor: glovo.Actor{PrincipalID: prn, Kind: glovo.ActorUser}})
		if err != nil {
			e.t.Fatalf("seed %d: %v", i, err)
		}
	}
}

// T7 and T12: two replicas race for the last slot of a tenant, from an empty
// counter table and right after a Sweep; the mutex row is created by
// ON CONFLICT DO NOTHING and Sweep leaves it.
func TestGlovoE2ETenantLimitRace(t *testing.T) {
	e := newE2E(t, e2eOpts{})
	ctx := context.Background()
	svc := &connect.Service{Store: e.store, HandoffBaseURL: e2eHandoff}
	for round, tenant := range []string{"alpha", "beta", "labs", "gamma"} {
		inst, err := e.store.Install(ctx, tenant, glovo.Actor{PrincipalID: prnOwner, Kind: glovo.ActorOwner})
		if err != nil {
			t.Fatal(err)
		}
		e.seedLive(tenant, 49, inst.InstallRevision)
		switch round {
		case 0:
			if n := e.count(`SELECT count(*) FROM glovo.glovo_rate_counters`); n != 0 {
				t.Fatalf("counter table not empty: %d", n)
			}
		case 1:
			e.adminExec(`INSERT INTO glovo.glovo_rate_counters VALUES ('owner_hour', 'alpha', 'prn_x', clock_timestamp() - interval '3 hours', 1, clock_timestamp())`)
			mutex := e.count(`SELECT count(*) FROM glovo.glovo_rate_counters WHERE scope = 'tenant_mutex'`)
			r, err := e.store.Sweep(ctx, 100)
			if err != nil || r.Counters != 1 {
				t.Fatalf("sweep: %+v %v", r, err)
			}
			if n := e.count(`SELECT count(*) FROM glovo.glovo_rate_counters WHERE scope = 'tenant_mutex'`); n != mutex || mutex == 0 {
				t.Fatalf("sweep touched the mutex rows: %d -> %d", mutex, n)
			}
		case 2:
			e.adminExec(`DELETE FROM glovo.glovo_rate_counters`) // right after a sweep: the mutex row is gone
		case 3:
			// Steady state: the mutex row exists, so only the row lock serializes.
			e.adminExec(`INSERT INTO glovo.glovo_rate_counters VALUES ('tenant_mutex', 'gamma', '', 'epoch', 0, clock_timestamp()) ON CONFLICT DO NOTHING`)
		}
		// A barrier after the limits: both replicas are held between the count and
		// the insert until both arrived (or 400 ms passed). With the L2a mutex the
		// second one waits for the first and never arrives; with the mutex
		// reverted both count 49 and both insert, and this test goes red.
		var bmu sync.Mutex
		arrived, both := 0, make(chan struct{})
		svc.AfterLimits = func(context.Context, pgx.Tx) error {
			bmu.Lock()
			arrived++
			if arrived == 2 {
				close(both)
			}
			bmu.Unlock()
			select {
			case <-both:
			case <-time.After(400 * time.Millisecond):
			}
			return nil
		}
		var wg sync.WaitGroup
		results := make([]error, 2)
		for i, prn := range []string{prnA1, prnA2} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, results[i] = svc.Connect(ctx, connect.JoinScope{Tenant: tenant, PrincipalID: prn, InstallRevision: inst.InstallRevision}, fmt.Sprintf("race-%d-%d", round, i))
			}()
		}
		wg.Wait()
		var ok, limited int
		for _, err := range results {
			var ge *glovo.Error
			switch {
			case err == nil:
				ok++
			case errors.As(err, &ge) && ge.Code == glovo.CodeRateLimited:
				limited++
			default:
				t.Fatalf("round %d: %v", round, err)
			}
		}
		if ok != 1 || limited != 1 {
			t.Fatalf("round %d: %d succeeded, %d refused; want exactly one of each", round, ok, limited)
		}
		if n := e.count(`SELECT count(*) FROM glovo.glovo_connections WHERE tenant_id = $1 AND state IN ('pending_handoff','pending_provider','active')`, tenant); n != 50 {
			t.Fatalf("round %d: %d live connections", round, n)
		}
	}
}

// T7: a handoff consume racing a revoke commits one or the other, and a
// connect racing a reinstall leaves no live connection on a stale revision.
func TestGlovoE2ERaces(t *testing.T) {
	e := newE2E(t, e2eOpts{})
	rev, _ := e.readyAlphaBeta()
	a1 := e.mint(prnA1, "alpha")
	ctx := context.Background()
	o1 := glovo.Owner{TenantID: "alpha", PrincipalID: prnA1}

	for i := 0; i < 8; i++ {
		id := e.connectAs(a1)
		ref := e.handoffAs(a1, id)
		var wg sync.WaitGroup
		var acode int
		wg.Add(2)
		go func() { defer wg.Done(); acode, _ = e.activate(id, rev, ref) }()
		go func() {
			defer wg.Done()
			_, _ = e.callJSON(http.MethodPost, facade+"/connections/"+id+"/revoke", a1, nil)
		}()
		wg.Wait()
		v, err := e.store.GetConnectionView(ctx, o1, id)
		if err != nil {
			t.Fatal(err)
		}
		// Whatever the order, the revoke ends the connection; an activation that
		// lost the race is refused and consumed nothing.
		if v.State != glovo.Revoked {
			t.Fatalf("round %d: state %s (activate %d)", i, v.State, acode)
		}
		if acode != http.StatusOK {
			if n := e.count(`SELECT count(*) FROM glovo.glovo_handoff_refs WHERE connection_id = $1 AND consumed_at IS NOT NULL`, id); n != 0 {
				t.Fatalf("round %d: a refused activation consumed the reference", i)
			}
		}
	}

	svc := e.routes.Connect
	for i := 0; i < 6; i++ {
		cur := e.installRevision("alpha")
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = svc.Connect(ctx, connect.JoinScope{Tenant: "alpha", PrincipalID: prnA2, InstallRevision: cur}, fmt.Sprintf("cr-%d", i))
		}()
		go func() {
			defer wg.Done()
			_, _ = e.callJSON(http.MethodPut, "/api/v1/glovo/tenants/alpha/installation", "tu:owner", map[string]any{"schema": wire.SchemaInstallationReq, "install_revision": cur})
		}()
		wg.Wait()
		now := e.installRevision("alpha")
		if n := e.count(`SELECT count(*) FROM glovo.glovo_connections WHERE tenant_id = 'alpha' AND state IN ('pending_handoff','pending_provider','active') AND install_revision < $1`, now); n != 0 {
			t.Fatalf("round %d: %d live connections on a stale revision", i, n)
		}
		_, _ = e.store.Revoke(ctx, glovo.Owner{TenantID: "alpha", PrincipalID: prnA2}, glovo.Actor{PrincipalID: prnA2, Kind: glovo.ActorUser}, e.liveID(prnA2), "user_revoked")
	}
}

func (e *e2eEnv) installRevision(tenant string) int64 {
	e.t.Helper()
	i, err := e.store.InstallRow(context.Background(), tenant)
	if err != nil || i == nil {
		e.t.Fatalf("install row: %v", err)
	}
	return i.InstallRevision
}

// liveID returns the id of the principal's live connection, or a placeholder.
func (e *e2eEnv) liveID(prn string) string {
	var id string
	err := e.pool.QueryRow(context.Background(), `SELECT connection_id FROM glovo.glovo_connections
 WHERE principal_id = $1 AND state IN ('pending_handoff','pending_provider','active') LIMIT 1`, prn).Scan(&id)
	if err != nil {
		return "gcn_none"
	}
	return id
}

// T8: identity confinement, driven by the route inventory.
func TestGlovoE2EIdentityConfinement(t *testing.T) {
	e := newE2E(t, e2eOpts{})
	e.readyAlphaBeta()
	routes := glovoRoutePaths(t, e)
	isWorker := func(p string) bool { return strings.HasPrefix(p, "/api/v1/glovo/worker/") }
	isFacade := func(p string) bool { return strings.HasPrefix(p, "/api/v1/glovo/facade/") }

	glovoTok := e.mint(prnA1, "alpha")
	supportTok := e.forge("https://support.mctl.ai/mcp", prnA1, "", "")
	for _, rt := range routes {
		// The worker: 403 outside the worker routes.
		if !isWorker(rt[1]) {
			if code, _ := e.call(rt[0], rt[1], e2eWorkerTok, "{}"); code != http.StatusForbidden {
				t.Errorf("worker on %s %s: %d", rt[0], rt[1], code)
			}
		}
		// A bridge provider: 403 on every Glovo route.
		if code, _ := e.call(rt[0], rt[1], "tu:bridge", "{}"); code != http.StatusForbidden {
			t.Errorf("bridge provider on %s %s: %d", rt[0], rt[1], code)
		}
		if isWorker(rt[1]) {
			// An admin, the service token, a support-audience token and a
			// Glovo-audience token are refused on worker routes.
			for name, tok := range map[string]string{"admin": "tu:root", "service": e2eServiceTk, "owner": "tu:owner"} {
				if code, _ := e.call(rt[0], rt[1], tok, "{}"); code != http.StatusForbidden {
					t.Errorf("%s on %s %s: %d", name, rt[0], rt[1], code)
				}
			}
			for name, tok := range map[string]string{"support audience": supportTok, "glovo audience": glovoTok} {
				if code, _ := e.call(rt[0], rt[1], tok, "{}"); code != http.StatusUnauthorized && code != http.StatusForbidden {
					t.Errorf("%s on %s %s: %d", name, rt[0], rt[1], code)
				}
			}
		}
		// A Glovo-audience token is 401 outside /api/v1/glovo/facade/*.
		if !isFacade(rt[1]) {
			if code, _ := e.call(rt[0], rt[1], glovoTok, "{}"); code != http.StatusUnauthorized {
				t.Errorf("glovo audience on %s %s: %d", rt[0], rt[1], code)
			}
		}
	}
	for _, rt := range [][2]string{
		{http.MethodGet, "/api/v1/whoami"}, {http.MethodPost, "/mcp"}, {http.MethodGet, "/api/v1/agents/dev-loop/x/approval"},
		{http.MethodPost, "/api/v1/agents/dev-loop/x/approve"}, {http.MethodPost, "/api/v1/bridge/commands/claim"},
	} {
		if code, _ := e.call(rt[0], rt[1], e2eWorkerTok, "{}"); code != http.StatusForbidden {
			t.Errorf("worker on %s %s: %d", rt[0], rt[1], code)
		}
		if code, _ := e.call(rt[0], rt[1], glovoTok, "{}"); code != http.StatusUnauthorized {
			t.Errorf("glovo audience on %s %s: %d", rt[0], rt[1], code)
		}
	}
	// A GET on a worker route is no route for the worker either.
	if code, _ := e.call(http.MethodGet, worker+"/check", e2eWorkerTok, nil); code != http.StatusForbidden {
		t.Errorf("worker GET: %d", code)
	}
}

// F1 (round 5): installation routes admit only the tenant role owner. A
// platform admin who is not an owner is refused; an owner who is also an admin
// is judged by the owner role.
func TestGlovoE2EInstallationOwnerOnly(t *testing.T) {
	e := newE2E(t, e2eOpts{})
	path := "/api/v1/glovo/tenants/alpha/installation"
	for _, m := range []string{http.MethodPut, http.MethodDelete} {
		if code, body := e.call(m, path, "tu:root", nil); code != http.StatusForbidden {
			t.Errorf("admin who is not an owner, %s: %d %s", m, code, body)
		}
	}
	// beta: the owner-admin owns alpha only.
	if code, _ := e.call(http.MethodPut, "/api/v1/glovo/tenants/beta/installation", "tu:owner-root", nil); code != http.StatusForbidden {
		t.Errorf("owner of another tenant: %d", code)
	}
	if code, _ := e.call(http.MethodPut, path, "tu:owner-root", nil); code != http.StatusCreated {
		t.Errorf("owner-admin: %d", code)
	}
	// An owner loses the role: refused at once, whatever the admin flag says.
	e.members.set("alpha", prnOwAdm, "developer")
	if code, _ := e.call(http.MethodDelete, path, "tu:owner-root", nil); code != http.StatusForbidden {
		t.Errorf("demoted owner-admin: %d", code)
	}
	if code, _ := e.call(http.MethodDelete, path, "tu:owner", nil); code != http.StatusOK {
		t.Errorf("owner delete: %d", code)
	}
	if code, m := e.callJSON(http.MethodDelete, path, "tu:owner", nil); code != http.StatusForbidden || errCode(m) != "no_install" {
		t.Errorf("second delete: %d %v", code, m)
	}
	// Forged body fields on the installation route.
	if code, _ := e.call(http.MethodPut, path, "tu:owner", `{"schema":"`+wire.SchemaInstallationReq+`","tenant":"beta"}`); code != http.StatusBadRequest {
		t.Errorf("forged installation body: %d", code)
	}
	// An unauthenticated and a Glovo-audience caller are refused.
	if code, _ := e.call(http.MethodPut, path, "", nil); code != http.StatusUnauthorized {
		t.Errorf("anonymous: %d", code)
	}
}

// T11: readiness. A runtime role with an extra or missing right, no purger or a
// disabled trigger closes every route.
func TestGlovoE2EReadiness(t *testing.T) {
	e := newE2E(t, e2eOpts{})
	e.readyAlphaBeta()
	allClosed := func(name string) {
		t.Helper()
		for _, rt := range glovoRoutePaths(t, e) {
			code, m := e.callJSON(rt[0], rt[1], "tu:owner", "{}")
			if code != http.StatusServiceUnavailable || errCode(m) != "not_ready" {
				t.Errorf("%s: %s %s: %d %v", name, rt[0], rt[1], code, m)
			}
		}
	}
	open := func(name string) {
		t.Helper()
		if code, _ := e.call(http.MethodPut, "/api/v1/glovo/tenants/alpha/installation", "tu:owner", nil); code == http.StatusServiceUnavailable {
			t.Errorf("%s: still closed", name)
		}
	}
	rt := e.rt
	for _, c := range []struct{ name, mutate, restore string }{
		{"extra right on glovo_rate_counters", `GRANT TRUNCATE ON glovo.glovo_rate_counters TO ` + rt, `REVOKE TRUNCATE ON glovo.glovo_rate_counters FROM ` + rt},
		{"missing right on glovo_handoff_refs", `REVOKE DELETE ON glovo.glovo_handoff_refs FROM ` + rt, `GRANT DELETE ON glovo.glovo_handoff_refs TO ` + rt},
		{"missing column right on glovo_handoff_refs", `REVOKE UPDATE (consumed_at) ON glovo.glovo_handoff_refs FROM ` + rt, `GRANT UPDATE (consumed_at) ON glovo.glovo_handoff_refs TO ` + rt},
		{"extra right on glovo_connect_requests", `GRANT TRIGGER ON glovo.glovo_connect_requests TO ` + rt, `REVOKE TRIGGER ON glovo.glovo_connect_requests FROM ` + rt},
		{"trigger disabled", `ALTER TABLE glovo.glovo_audit_events DISABLE TRIGGER glovo_audit_events_immutable`, `ALTER TABLE glovo.glovo_audit_events ENABLE TRIGGER glovo_audit_events_immutable`},
	} {
		e.adminExec(c.mutate)
		allClosed(c.name)
		if err := e.store.Ready(context.Background()); !errors.Is(err, &glovo.Error{Code: glovo.CodeNotReady}) {
			t.Errorf("%s: Ready = %v", c.name, err)
		}
		e.adminExec(c.restore)
		open(c.name)
	}
	// No DDL runs under the runtime role.
	if _, err := e.pool.Exec(context.Background(), `CREATE TABLE glovo.glovo_rogue (a int)`); err == nil {
		t.Error("the runtime role created a table")
	}
	if _, err := e.pool.Exec(context.Background(), `ALTER TABLE glovo.glovo_handoff_refs ADD COLUMN x int`); err == nil {
		t.Error("the runtime role altered a table")
	}

	// WithEndPurgerRequired(true) with no purger installed: end_purger_missing.
	e2 := newE2E(t, e2eOpts{noPurger: true})
	err := e2.store.Ready(context.Background())
	var nr *glovo.NotReadyError
	if !errors.As(err, &nr) || nr.Reason != glovo.NotReadyPurger {
		t.Errorf("no purger: %v", err)
	}
	for _, rt := range glovoRoutePaths(t, e2) {
		if code, _ := e2.call(rt[0], rt[1], "tu:owner", "{}"); code != http.StatusServiceUnavailable {
			t.Errorf("no purger: %s %s: %d", rt[0], rt[1], code)
		}
	}
	// No worker credential: every route is not_ready.
	e3 := newE2E(t, e2eOpts{noWorker: true})
	for _, rt := range glovoRoutePaths(t, e3) {
		if code, _ := e3.call(rt[0], rt[1], "tu:owner", "{}"); code != http.StatusServiceUnavailable {
			t.Errorf("no worker credential: %s %s: %d", rt[0], rt[1], code)
		}
	}
}

// T12: the join-route path.
func TestGlovoE2EJoinPath(t *testing.T) {
	e := newE2E(t, e2eOpts{storeOptions: []glovo.Option{glovo.WithLockTimeout(400 * time.Millisecond)}})
	rev, _ := e.readyAlphaBeta()
	ctx := context.Background()
	a1 := e.mint(prnA1, "alpha")

	// The facade route and Service.Connect are the same code: a counting
	// AfterLimits runs on both and never on a replay.
	var mu sync.Mutex
	runs := 0
	svc := &connect.Service{Store: e.store, HandoffBaseURL: e2eHandoff, AfterLimits: func(context.Context, pgx.Tx) error {
		mu.Lock()
		runs++
		mu.Unlock()
		return nil
	}}
	e.routes.Connect = svc
	e.connectAs(a1)
	if runs != 1 {
		t.Fatalf("facade connect ran AfterLimits %d times", runs)
	}
	sc2 := connect.JoinScope{Tenant: "alpha", PrincipalID: prnA2, InstallRevision: rev}
	out, err := svc.Connect(ctx, sc2, "join-1")
	if err != nil || out.Replayed || runs != 2 {
		t.Fatalf("join connect: %v %+v runs=%d", err, out, runs)
	}
	if !strings.HasPrefix(out.HandoffURL, e2eHandoff+"/ghr_") || out.HandoffExpiresAt.IsZero() {
		t.Fatalf("handoff url %q", out.HandoffURL)
	}
	// A replay returns Replayed and a fresh handoff_url; the older reference no
	// longer activates; no counter and no AfterLimits move.
	counter := func() int {
		return e.count(`SELECT coalesce(sum(count), 0)::int FROM glovo.glovo_rate_counters WHERE scope = 'owner_hour' AND principal_id = $1`, prnA2)
	}
	before := counter()
	out2, err := svc.Connect(ctx, sc2, "join-1")
	if err != nil || !out2.Replayed || out2.HandoffURL == "" || out2.HandoffURL == out.HandoffURL || runs != 2 || counter() != before {
		t.Fatalf("replay: %v %+v runs=%d counter %d -> %d", err, out2, runs, before, counter())
	}
	ref1 := out.HandoffURL[len(e2eHandoff)+1:]
	ref2 := out2.HandoffURL[len(e2eHandoff)+1:]
	if code, _ := e.activate(out.Connection.ConnectionID, rev, ref1); code != http.StatusNotFound {
		t.Fatalf("older reference activated: %d", code)
	}
	if code, m := e.activate(out.Connection.ConnectionID, rev, ref2); code != http.StatusOK {
		t.Fatalf("fresh reference: %d %v", code, m)
	}
	// Current.
	if c, err := svc.Current(ctx, sc2); err != nil || c.State != glovo.Active {
		t.Fatalf("current: %v %v", c, err)
	}
	if _, err := svc.Current(ctx, connect.JoinScope{Tenant: "alpha", PrincipalID: prnU3, InstallRevision: rev}); !errors.Is(err, glovo.Refuse(glovo.CodeNoConnection)) {
		t.Fatalf("current with none: %v", err)
	}
	// Unset GLOVO_SYNTHETIC_HANDOFF_BASE_URL is not_ready.
	if _, err := (&connect.Service{Store: e.store}).Connect(ctx, sc2, "join-2"); !errors.Is(err, glovo.Refuse(glovo.CodeNotReady)) {
		t.Fatalf("no base url: %v", err)
	}

	// A lapsed live connection: the join-path Connect succeeds, and lapsed rows
	// do not fill the tenant cap.
	e.adminExec(`UPDATE glovo.glovo_connections SET expires_at = clock_timestamp() - interval '1 minute' WHERE connection_id = $1`, out.Connection.ConnectionID)
	if _, err := svc.Current(ctx, sc2); !errors.Is(err, glovo.Refuse(glovo.CodeConnectionExpired)) {
		t.Fatalf("current after lapse: %v", err)
	}
	out3, err := svc.Connect(ctx, sc2, "join-3")
	if err != nil || out3.Connection.State != glovo.PendingHandoff || out3.Connection.ConnectionID == out.Connection.ConnectionID {
		t.Fatalf("connect after lapse: %v %+v", err, out3)
	}
	if st := e.count(`SELECT count(*) FROM glovo.glovo_connections WHERE connection_id = $1 AND state = 'expired'`, out.Connection.ConnectionID); st != 1 {
		t.Fatal("the lapsed connection was not persisted as expired")
	}

	// 11 in an hour refuse the 11th, through the adapter path.
	o3 := glovo.Owner{TenantID: "alpha", PrincipalID: prnU3}
	sc3 := connect.JoinScope{Tenant: "alpha", PrincipalID: prnU3, InstallRevision: rev}
	for i := 1; i <= 10; i++ {
		o, err := svc.Connect(ctx, sc3, fmt.Sprintf("u3-%d", i))
		if err != nil {
			t.Fatalf("u3 connect %d: %v", i, err)
		}
		if i == 10 {
			// The replay of the 10th: no counter moves.
			n := e.count(`SELECT coalesce(sum(count), 0)::int FROM glovo.glovo_rate_counters WHERE scope = 'owner_hour' AND principal_id = $1`, prnU3)
			if r, err := svc.Connect(ctx, sc3, "u3-10"); err != nil || !r.Replayed {
				t.Fatalf("replay at the 10th slot: %v %+v", err, r)
			}
			if m := e.count(`SELECT coalesce(sum(count), 0)::int FROM glovo.glovo_rate_counters WHERE scope = 'owner_hour' AND principal_id = $1`, prnU3); m != n || n != 10 {
				t.Fatalf("counter %d -> %d", n, m)
			}
			break
		}
		_, _ = e.store.Revoke(ctx, o3, glovo.Actor{PrincipalID: prnU3, Kind: glovo.ActorUser}, o.Connection.ConnectionID, "user_revoked")
	}
	var ge *glovo.Error
	_, _ = e.store.Revoke(ctx, o3, glovo.Actor{PrincipalID: prnU3, Kind: glovo.ActorUser}, e.liveID(prnU3), "user_revoked")
	if _, err := svc.Connect(ctx, sc3, "u3-11"); !errors.As(err, &ge) || ge.Code != glovo.CodeRateLimited {
		t.Fatalf("eleventh connect: %v", err)
	}

	// The 50th slot: a replay returns Replayed and moves nothing.
	e.seedLive("alpha", 47, rev) // a1, a2 (live: out3) and the 47 seeds are 49 live
	scB := connect.JoinScope{Tenant: "alpha", PrincipalID: prnB1, InstallRevision: rev}
	if _, err := svc.Connect(ctx, scB, "b-50"); err != nil {
		t.Fatalf("50th: %v", err)
	}
	if r, err := svc.Connect(ctx, scB, "b-50"); err != nil || !r.Replayed {
		t.Fatalf("replay at the 50th slot: %v %+v", err, r)
	}
	if _, err := svc.Connect(ctx, connect.JoinScope{Tenant: "alpha", PrincipalID: e2ePRN('H'), InstallRevision: rev}, "h-51"); !errors.As(err, &ge) || ge.Code != glovo.CodeRateLimited {
		t.Fatalf("51st: %v", err)
	}

	// tenant_busy: another transaction holds the L2a mutex row of beta.
	e.adminExec(`INSERT INTO glovo.glovo_rate_counters VALUES ('tenant_mutex', 'beta', '', 'epoch', 0, clock_timestamp()) ON CONFLICT DO NOTHING`)
	conn, err := pgx.Connect(ctx, e.rtURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT 1 FROM glovo.glovo_rate_counters WHERE scope = 'tenant_mutex' AND tenant_id = 'beta' FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	_, err = svc.Connect(ctx, connect.JoinScope{Tenant: "beta", PrincipalID: prnB1, InstallRevision: e.installRevision("beta")}, "busy-1")
	_ = tx.Rollback(ctx)
	if glovo.AsError(err).Code != glovo.CodeTenantBusy {
		t.Fatalf("held mutex: %v", err)
	}
}

// T13: the worker routes use only the gcn_ id. A version change between the
// by-id read and ActivateTx is stale_version and commits nothing. No code
// outside the store reads glovo_connections.
func TestGlovoE2EWorkerOwnerPath(t *testing.T) {
	e := newE2E(t, e2eOpts{})
	rev, betaRev := e.readyAlphaBeta()
	a1, b1 := e.mint(prnA1, "alpha"), e.mint(prnB1, "beta")
	idA, idB := e.connectAs(a1), e.connectAs(b1)
	refA, refB := e.handoffAs(a1, idA), e.handoffAs(b1, idB)
	// Tenants differ between the two calls; only the gcn_ id names the owner.
	if code, m := e.activate(idA, rev, refA); code != http.StatusOK {
		t.Fatalf("alpha activate: %d %v", code, m)
	}
	if code, m := e.activate(idB, betaRev, refB); code != http.StatusOK {
		t.Fatalf("beta activate: %d %v", code, m)
	}
	if code, m := e.check(idB, betaRev); code != http.StatusOK || m["tenant"] != "beta" {
		t.Fatalf("beta check: %d %v", code, m)
	}
	if code, m := e.expire(idA); code != http.StatusOK || m["state"] != "expired" {
		t.Fatalf("alpha expire: %d %v", code, m)
	}

	// stale_version: nothing is committed, the reference is not consumed.
	ctx := context.Background()
	o2 := glovo.Owner{TenantID: "alpha", PrincipalID: prnA2}
	a2 := e.mint(prnA2, "alpha")
	idC := e.connectAs(a2)
	refC := e.handoffAs(a2, idC)
	view, err := e.store.WorkerConnectionView(ctx, idC)
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.store.ActivateWithHandoff(ctx, glovo.ActivateInput{Owner: o2, ConnectionID: idC, ExpectedVersion: view.Version + 1,
		ExpectedInstallRevision: rev, ExpiresIn: time.Hour, Actor: glovo.Actor{PrincipalID: "worker", Kind: glovo.ActorWorker}}, refC)
	if glovo.AsError(err).Code != glovo.CodeStaleVersion {
		t.Fatalf("stale version: %v", err)
	}
	if n := e.count(`SELECT count(*) FROM glovo.glovo_handoff_refs WHERE connection_id = $1 AND consumed_at IS NULL`, idC); n != 1 {
		t.Fatal("a refused activation consumed the reference")
	}
	if v, _ := e.store.GetConnectionView(ctx, o2, idC); v.State != glovo.PendingHandoff || v.Version != view.Version {
		t.Fatalf("a refused activation changed the connection: %+v", v)
	}

	// Source scan: nothing outside package glovo reads glovo_connections, and
	// only the worker handlers call the owner-less read.
	for _, dir := range []string{".", "../glovo/connect", "../glovo/wire"} {
		files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			src, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(src), "glovo.glovo_connections") {
				t.Errorf("%s reads glovo_connections", f)
			}
			if (strings.Contains(string(src), "WorkerConnectionView(") || strings.Contains(string(src), "GetConnectionForWorker(")) &&
				filepath.Base(f) != "handlers_glovo_worker.go" {
				t.Errorf("%s calls the owner-less worker read", f)
			}
		}
	}
}
