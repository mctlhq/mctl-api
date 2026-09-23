package api

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

func sealBody(canonical string, sequence int) map[string]any {
	return map[string]any{
		"execution_sequence": sequence,
		"canonical_b64":      base64.StdEncoding.EncodeToString([]byte(canonical)),
		"content_hash":       workitems.HashCanonical([]byte(canonical)),
		"strategy":           "investigator",
		"strategy_version":   "v1",
	}
}

func TestWorkItemSnapshots_SealReplayDivergeAndRead(t *testing.T) {
	e := newWorkItemsEnv(t)
	alice, svc := e.user("alice"), auth.NewServiceUser()
	id := e.open(alice, map[string]any{"origin_surface": "telegram"})["id"].(string)
	res := e.do(svc, "POST", "/api/v1/work-items/"+id+"/executions", map[string]any{"engine": "temporal", "engine_ref": "dev-loop-1", "phase": "Running"})
	execID := res.body["execution"].(map[string]any)["id"].(string)
	path := "/api/v1/work-items/" + id + "/executions/" + execID + "/snapshot"
	canonical := `{"a":"<b>&","n":1}` // HTML-escapable bytes survive base64

	res = e.do(svc, "POST", path, sealBody(canonical, 1))
	if res.code != http.StatusCreated {
		t.Fatalf("seal = %d %s", res.code, res.raw)
	}
	snap := res.body["snapshot"].(map[string]any)
	snapID := snap["id"].(string)
	if !strings.HasPrefix(snapID, workitems.SnapshotIDPrefix) || snap["execution_id"] != execID || snap["produced_by"] != "service:"+auth.ServiceUserID {
		t.Fatalf("snapshot = %v", snap)
	}

	// Replay: the same execution with the same bytes is 200, same snapshot.
	res = e.do(svc, "POST", path, sealBody(canonical, 1))
	if res.code != http.StatusOK || res.body["snapshot"].(map[string]any)["id"] != snapID {
		t.Fatalf("replay = %d %s", res.code, res.raw)
	}
	// Divergence: different bytes for the same execution.
	res = e.do(svc, "POST", path, sealBody(`{"a":"other"}`, 1))
	if res.code != http.StatusConflict || code(res) != wiCodeSnapshotDivergence {
		t.Fatalf("diverge = %d %s", res.code, res.raw)
	}

	// Every read returns the exact bytes; the owner may read, others not.
	for _, p := range []string{path, "/api/v1/work-items/" + id + "/snapshots/" + snapID} {
		res = e.do(alice, "GET", p, nil)
		got, _ := base64.StdEncoding.DecodeString(res.body["snapshot"].(map[string]any)["canonical_b64"].(string))
		if res.code != http.StatusOK || string(got) != canonical {
			t.Fatalf("GET %s = %d %s", p, res.code, res.raw)
		}
	}
	res = e.do(alice, "GET", "/api/v1/work-items/"+id+"/snapshots", nil)
	list := res.body["snapshots"].([]any)
	if res.code != http.StatusOK || len(list) != 1 {
		t.Fatalf("list = %d %s", res.code, res.raw)
	}
	if _, hasBytes := list[0].(map[string]any)["canonical_b64"]; hasBytes || list[0].(map[string]any)["id"] != snapID {
		t.Fatalf("a listing carries no bytes: %s", res.raw)
	}
	// The item view points at it.
	res = e.do(alice, "GET", "/api/v1/work-items/"+id, nil)
	if latest, _ := res.body["latest_snapshot"].(map[string]any); latest["id"] != snapID || latest["execution_id"] != execID {
		t.Fatalf("view = %s", res.raw)
	}
	res = e.do(auth.NewGitHubUser("mallory", []string{"elsewhere"}), "GET", path, nil)
	if res.code != http.StatusNotFound || code(res) != wiCodeNotFound {
		t.Fatalf("stranger = %d %s", res.code, res.raw)
	}
	// A missing snapshot or execution is not "the work item is gone".
	res = e.do(alice, "GET", "/api/v1/work-items/"+id+"/snapshots/cs_missing", nil)
	if res.code != http.StatusNotFound || code(res) != wiCodeSnapshotNotFound {
		t.Fatalf("missing snapshot = %d %s", res.code, res.raw)
	}
	res = e.do(svc, "POST", "/api/v1/work-items/"+id+"/executions/we_missing/snapshot", sealBody(canonical, 1))
	if res.code != http.StatusNotFound || code(res) != wiCodeExecutionNotFound {
		t.Fatalf("missing execution = %d %s", res.code, res.raw)
	}
}

func TestWorkItemSnapshots_OnlyAServiceSeals(t *testing.T) {
	e := newWorkItemsEnv(t)
	alice, svc := e.user("alice"), auth.NewServiceUser()
	id := e.open(alice, nil)["id"].(string)
	res := e.do(svc, "POST", "/api/v1/work-items/"+id+"/executions", map[string]any{"engine": "temporal", "engine_ref": "dev-loop-1", "phase": "Running"})
	path := "/api/v1/work-items/" + id + "/executions/" + res.body["execution"].(map[string]any)["id"].(string) + "/snapshot"
	surface := auth.NewSurfaceUser("telegram")
	for name, u := range map[string]*auth.User{
		"owner":   alice,
		"admin":   auth.NewGitHubUser("root", []string{"admins"}),
		"surface": surface,
		"relayed": auth.NewRelayedUser("alice", []string{e.tenant}, surface),
	} {
		res := e.do(u, "POST", path, sealBody(`{"a":1}`, 1))
		if res.code != http.StatusForbidden || code(res) != wiCodeSnapshotForbidden {
			t.Errorf("%s: seal = %d %s", name, res.code, res.raw)
		}
	}
	res = e.do(alice, "GET", "/api/v1/work-items/"+id+"/snapshots", nil)
	if list := res.body["snapshots"].([]any); len(list) != 0 {
		t.Fatalf("snapshots = %v", list)
	}
	// With none sealed the view carries an explicit null.
	res = e.do(alice, "GET", "/api/v1/work-items/"+id, nil)
	if v, present := res.body["latest_snapshot"]; !present || v != nil {
		t.Fatalf("view = %s", res.raw)
	}
}

func TestWorkItemSnapshots_RejectsBadBodies(t *testing.T) {
	e := newWorkItemsEnv(t)
	alice, svc := e.user("alice"), auth.NewServiceUser()
	id := e.open(alice, nil)["id"].(string)
	res := e.do(svc, "POST", "/api/v1/work-items/"+id+"/executions", map[string]any{"engine": "temporal", "engine_ref": "dev-loop-1", "phase": "Running"})
	path := "/api/v1/work-items/" + id + "/executions/" + res.body["execution"].(map[string]any)["id"].(string) + "/snapshot"
	notB64 := sealBody(`{"a":1}`, 1)
	notB64["canonical_b64"] = "{not base64}"
	wrongHash := sealBody(`{"a":1}`, 1)
	wrongHash["content_hash"] = workitems.HashCanonical([]byte(`{"a":2}`))
	wrongSeq := sealBody(`{"a":1}`, 2)
	actor := sealBody(`{"a":1}`, 1)
	actor["actor"] = "service:someone-else"
	unknown := sealBody(`{"a":1}`, 1)
	unknown["extra"] = true
	for name, body := range map[string]map[string]any{"not base64": notB64, "wrong hash": wrongHash, "wrong sequence": wrongSeq, "unknown field": unknown} {
		if res := e.do(svc, "POST", path, body); res.code != http.StatusBadRequest || code(res) != wiCodeInvalid {
			t.Errorf("%s: %d %s", name, res.code, res.raw)
		}
	}
	if res := e.do(svc, "POST", path, sealBody(`{"a":1}`, 1), "Idempotency-Key", "k-1"); res.code != http.StatusBadRequest || code(res) != wiCodeInvalid {
		t.Errorf("idempotency key: %d %s", res.code, res.raw)
	}
	if res := e.do(svc, "POST", path, actor); res.code != http.StatusBadRequest || code(res) != wiCodeActorNotAccepted {
		t.Errorf("actor: %d %s", res.code, res.raw)
	}
}
