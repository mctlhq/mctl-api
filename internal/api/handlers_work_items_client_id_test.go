package api

import (
	"net/http"
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
)

// mctl-api#883: the OAuth client a work item, intent or event names comes
// only from the verified access token, never from the request.

// clientUser authenticates login through a real access token minted by the
// refresh grant for a newly registered client, so OAuthClientID comes from
// the signed claim. It returns the user and the client id.
func (e *workItemsEnv) clientUser(login, clientName string) (*auth.User, string) {
	e.t.Helper()
	o := auth.NewOAuthServer("https://api.example", "gh-client", "gh-secret", []byte("test-secret-for-client-id-tests"), nil, nil)
	clientID := o.RegisterClient(clientName, []string{"https://" + clientName + ".example/callback"}).ClientID
	refresh, err := o.IssueRefreshToken(login, "", []string{e.tenant}, clientID)
	if err != nil {
		e.t.Fatal(err)
	}
	access, _, err := o.RefreshAccessToken(refresh, clientID)
	if err != nil {
		e.t.Fatal(err)
	}
	u, err := o.ValidateJWT(access)
	if err != nil {
		e.t.Fatal(err)
	}
	if u.OAuthClientID() != clientID {
		e.t.Fatalf("minted user client = %q, want %q", u.OAuthClientID(), clientID)
	}
	// Tenant membership is decided outside the token in this mode; give the
	// verified user the same groups the plain test users get.
	u.Groups = []string{e.tenant}
	return u, clientID
}

func TestWorkItemsRecordTheTokensClient(t *testing.T) {
	e := newWorkItemsEnv(t)
	viaClaude, claude := e.clientUser("alice", "claude")
	viaChatGPT, chatgpt := e.clientUser("alice", "chatgpt")
	if claude == chatgpt {
		t.Fatal("the two registered clients must have different ids")
	}

	item := e.open(viaClaude, nil)
	id := item["id"].(string)
	if item["origin_client_id"] != claude {
		t.Fatalf("origin_client_id = %v, want %q", item["origin_client_id"], claude)
	}

	for _, c := range []struct {
		user *auth.User
		text string
	}{{viaClaude, "from claude"}, {viaChatGPT, "from chatgpt"}} {
		res := e.do(c.user, "POST", "/api/v1/work-items/"+id+"/intents", map[string]any{"text": c.text})
		if res.code != http.StatusCreated {
			t.Fatalf("append %q = %d %s", c.text, res.code, res.raw)
		}
	}
	res := e.do(viaClaude, "GET", "/api/v1/work-items/"+id+"/intents", nil)
	list, _ := res.body["intents"].([]any)
	if res.code != http.StatusOK || len(list) != 2 {
		t.Fatalf("list = %d %s", res.code, res.raw)
	}
	first, second := list[0].(map[string]any), list[1].(map[string]any)
	if first["actor_client_id"] != claude || second["actor_client_id"] != chatgpt {
		t.Fatalf("intent clients = %v, %v", first["actor_client_id"], second["actor_client_id"])
	}
	if first["actor_principal"] != second["actor_principal"] || first["surface"] != second["surface"] {
		t.Fatalf("the two clients must differ only by client id: %v vs %v", first, second)
	}

	// A credential that is not an mctl-api OAuth access token records "".
	plain := e.user("alice")
	res = e.do(plain, "POST", "/api/v1/work-items/"+id+"/intents", map[string]any{"text": "plain"})
	if res.code != http.StatusCreated {
		t.Fatalf("plain append = %d %s", res.code, res.raw)
	}
	if got := res.body["intent"].(map[string]any)["actor_client_id"]; got != "" {
		t.Fatalf("plain user client = %v, want empty", got)
	}
}

func TestWorkItemsRefuseClientIdentityInTheBody(t *testing.T) {
	e := newWorkItemsEnv(t)
	alice, _ := e.clientUser("alice", "claude")
	id := e.open(alice, nil)["id"].(string)

	for _, key := range []string{"actor_client_id", "origin_client_id", "client_id"} {
		res := e.do(alice, "POST", "/api/v1/work-items", map[string]any{"tenant": e.tenant, "title": "forged", key: "https://evil.example/client"})
		if res.code != http.StatusBadRequest || res.body["code"] != "actor_not_accepted" {
			t.Errorf("create with %s = %d %s, want 400 actor_not_accepted", key, res.code, res.raw)
		}
		res = e.do(alice, "POST", "/api/v1/work-items/"+id+"/intents", map[string]any{"text": "forged", key: "https://evil.example/client"})
		if res.code != http.StatusBadRequest || res.body["code"] != "actor_not_accepted" {
			t.Errorf("append with %s = %d %s, want 400 actor_not_accepted", key, res.code, res.raw)
		}
	}
	res := e.do(alice, "GET", "/api/v1/work-items/"+id+"/intents", nil)
	if list, _ := res.body["intents"].([]any); res.code != http.StatusOK || len(list) != 0 {
		t.Fatalf("refused appends stored something: %d %s", res.code, res.raw)
	}
}
