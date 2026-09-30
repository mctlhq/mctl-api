package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

func TestWorkItemIntents_UnconfiguredStoreAnswers503(t *testing.T) {
	h := &Handlers{}
	r := workItemsRouter(h)
	for _, rt := range [][2]string{
		{"GET", "/api/v1/work-items/wi_x/intents"},
		{"GET", "/api/v1/work-items/wi_x/intents/1"},
	} {
		req := httptest.NewRequest(rt[0], rt[1], strings.NewReader(""))
		req = req.WithContext(auth.WithUser(req.Context(), auth.NewGitHubUser("alice", []string{"acme"})))
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s %s = %d, want 503", rt[0], rt[1], rec.Code)
		}
	}
}

func TestWorkItemIntents_Unauthenticated(t *testing.T) {
	e := newWorkItemsEnv(t)
	for _, path := range []string{"/api/v1/work-items/wi_x/intents", "/api/v1/work-items/wi_x/intents/1"} {
		if res := e.do(nil, "GET", path, nil); res.code != http.StatusUnauthorized {
			t.Errorf("GET %s anonymous = %d %s", path, res.code, res.raw)
		}
	}
}

func TestWorkItemIntents_ListAndGet(t *testing.T) {
	e := newWorkItemsEnv(t)
	alice := e.user("alice")
	id := e.open(alice, nil)["id"].(string)

	var intentIDs []string
	for _, text := range []string{"first ask", "second ask", "third ask"} {
		res := e.do(alice, "POST", "/api/v1/work-items/"+id+"/intents", map[string]any{"text": text})
		if res.code != http.StatusCreated {
			t.Fatalf("append %q = %d %s", text, res.code, res.raw)
		}
		intentIDs = append(intentIDs, jsonNum(res.body["intent"].(map[string]any)["id"]))
	}

	// List: ascending id, correct shape, no bytes beyond the contract.
	res := e.do(alice, "GET", "/api/v1/work-items/"+id+"/intents", nil)
	if res.code != http.StatusOK {
		t.Fatalf("list = %d %s", res.code, res.raw)
	}
	list, _ := res.body["intents"].([]any)
	if len(list) != 3 || res.body["truncated"] != false || res.body["limit"] != float64(50) || res.body["schema_version"] != workitems.SchemaVersion {
		t.Fatalf("list = %s", res.raw)
	}
	first := list[0].(map[string]any)
	if first["text"] != "first ask" || first["text_redacted"] != false || first["work_item_id"] != id {
		t.Fatalf("first intent = %v", first)
	}

	// A service principal (the execution platform) can read too.
	svc := auth.NewServiceUser()
	if res := e.do(svc, "GET", "/api/v1/work-items/"+id+"/intents", nil); res.code != http.StatusOK {
		t.Fatalf("service list = %d %s", res.code, res.raw)
	}

	// Paginate with after_id and a small limit.
	res = e.do(alice, "GET", "/api/v1/work-items/"+id+"/intents?limit=2", nil)
	page1, _ := res.body["intents"].([]any)
	if res.code != http.StatusOK || len(page1) != 2 || res.body["truncated"] != true {
		t.Fatalf("page1 = %d %s", res.code, res.raw)
	}
	afterID := page1[len(page1)-1].(map[string]any)["id"]
	res = e.do(alice, "GET", "/api/v1/work-items/"+id+"/intents?limit=2&after_id="+jsonNum(afterID), nil)
	page2, _ := res.body["intents"].([]any)
	if res.code != http.StatusOK || len(page2) != 1 || res.body["truncated"] != false {
		t.Fatalf("page2 = %d %s", res.code, res.raw)
	}

	// Get one.
	res = e.do(alice, "GET", "/api/v1/work-items/"+id+"/intents/"+intentIDs[1], nil)
	if res.code != http.StatusOK {
		t.Fatalf("get = %d %s", res.code, res.raw)
	}
	got := res.body["intent"].(map[string]any)
	if jsonNum(got["id"]) != intentIDs[1] || got["text"] != "second ask" {
		t.Fatalf("get intent = %v, want id %s", got, intentIDs[1])
	}
}

// jsonNum renders a JSON-decoded intent id (a float64, since it carries no
// int64 tag) back to its decimal string for use in a URL or query string.
func jsonNum(v any) string {
	switch n := v.(type) {
	case float64:
		return strconv.FormatInt(int64(n), 10)
	case string:
		return n
	default:
		return ""
	}
}

func TestWorkItemIntents_CrossItemAndBadParams(t *testing.T) {
	e := newWorkItemsEnv(t)
	alice := e.user("alice")
	a := e.open(alice, nil)["id"].(string)
	b := e.open(alice, nil)["id"].(string)
	res := e.do(alice, "POST", "/api/v1/work-items/"+a+"/intents", map[string]any{"text": "belongs to a"})
	if res.code != http.StatusCreated {
		t.Fatalf("append = %d %s", res.code, res.raw)
	}
	intentID := res.body["intent"].(map[string]any)["id"]

	// The id exists, but on a different work item: intent_not_found, never
	// work_item_not_found.
	res = e.do(alice, "GET", "/api/v1/work-items/"+b+"/intents/"+jsonNum(intentID), nil)
	if res.code != http.StatusNotFound || code(res) != xrCodeIntentNotFound {
		t.Fatalf("cross-item get = %d %s", res.code, res.raw)
	}
	res = e.do(alice, "GET", "/api/v1/work-items/"+a+"/intents/not-a-number", nil)
	if res.code != http.StatusNotFound || code(res) != xrCodeIntentNotFound {
		t.Fatalf("non-numeric id = %d %s", res.code, res.raw)
	}

	for _, q := range []string{"?limit=0", "?limit=101", "?limit=abc", "?after_id=-1", "?after_id=abc"} {
		res := e.do(alice, "GET", "/api/v1/work-items/"+a+"/intents"+q, nil)
		if res.code != http.StatusBadRequest || code(res) != wiCodeInvalid {
			t.Errorf("%s = %d %s", q, res.code, res.raw)
		}
	}
}

func TestWorkItemIntents_VisibilityIsNeverForbidden(t *testing.T) {
	e := newWorkItemsEnv(t)
	alice := e.user("alice")
	tenantItem := e.open(alice, nil)["id"].(string)
	privateItem := e.open(alice, map[string]any{"visibility": "private"})["id"].(string)
	e.do(alice, "POST", "/api/v1/work-items/"+tenantItem+"/intents", map[string]any{"text": "x"})
	e.do(alice, "POST", "/api/v1/work-items/"+privateItem+"/intents", map[string]any{"text": "x"})

	stranger := auth.NewGitHubUser("mallory", []string{"elsewhere"})
	otherOwner := auth.NewGitHubUser("bob", []string{e.tenant})
	for name, u := range map[string]*auth.User{"foreign tenant": stranger, "other owner, private item": otherOwner} {
		item := tenantItem
		if name == "other owner, private item" {
			item = privateItem
		}
		for _, path := range []string{"/api/v1/work-items/" + item + "/intents", "/api/v1/work-items/" + item + "/intents/1"} {
			res := e.do(u, "GET", path, nil)
			if res.code != http.StatusNotFound || code(res) != wiCodeNotFound {
				t.Errorf("%s: GET %s = %d %s, want 404 work_item_not_found", name, path, res.code, res.raw)
			}
		}
	}
}

func TestWorkItemIntents_ReadsWriteNothing(t *testing.T) {
	e := newWorkItemsEnv(t)
	alice := e.user("alice")
	id := e.open(alice, nil)["id"].(string)
	e.do(alice, "POST", "/api/v1/work-items/"+id+"/intents", map[string]any{"text": "one"})

	before, err := e.h.opts.WorkItems.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	eventsBefore, err := e.h.opts.WorkItems.Events(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	auditBefore := len(e.audit.List(1000))

	e.do(alice, "GET", "/api/v1/work-items/"+id+"/intents", nil)
	e.do(alice, "GET", "/api/v1/work-items/"+id+"/intents?limit=1", nil)

	after, err := e.h.opts.WorkItems.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	eventsAfter, err := e.h.opts.WorkItems.Events(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if after.StateVersion != before.StateVersion || len(eventsAfter) != len(eventsBefore) {
		t.Fatalf("reads mutated state: version %d->%d, events %d->%d",
			before.StateVersion, after.StateVersion, len(eventsBefore), len(eventsAfter))
	}
	if got := len(e.audit.List(1000)); got != auditBefore {
		t.Fatalf("reads produced %d new audit rows", got-auditBefore)
	}
}
