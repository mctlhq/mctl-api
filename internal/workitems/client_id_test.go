package workitems

import (
	"context"
	"strconv"
	"testing"
)

// mctl-api#883: the OAuth client of the authenticating token is recorded on
// the work item, its events and its intents, and reads back on every path.

func withClient(m Mutation, clientID string) Mutation {
	m.ActorClientID = clientID
	return m
}

// withKey sets the idempotency key and a request hash derived from the
// text, so a replay with the same text matches the stored request.
func withKey(m Mutation, key, text string) Mutation {
	m.IdempotencyKey, m.RequestHash = key, "h-"+text
	return m
}

func TestWorkItemWritesRecordClientID(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	const claude, chatgpt = "https://claude.ai/oauth/client.json", "https://chatgpt.com/oauth/client.json"

	w := open(t, s, CreateInput{Mutation: withClient(as("github:alice"), claude)})
	if w.OriginClientID != claude {
		t.Fatalf("created item origin_client_id = %q, want %q", w.OriginClientID, claude)
	}
	got, err := s.Get(ctx, w.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.OriginClientID != claude {
		t.Fatalf("read item origin_client_id = %q", got.OriginClientID)
	}

	// Same principal, two clients: each intent keeps its own client.
	first, _, err := s.AppendIntent(ctx, IntentInput{Mutation: withKey(withClient(as("github:alice"), claude), "k1", "from claude"), WorkItemID: w.ID, Text: "from claude"})
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := s.AppendIntent(ctx, IntentInput{Mutation: withKey(withClient(as("github:alice"), chatgpt), "k2", "from chatgpt"), WorkItemID: w.ID, Text: "from chatgpt"})
	if err != nil {
		t.Fatal(err)
	}
	if first.ActorClientID != claude || second.ActorClientID != chatgpt {
		t.Fatalf("fresh intents client ids = %q, %q", first.ActorClientID, second.ActorClientID)
	}

	// A replay from another client returns the originally recorded client.
	replayed, created, err := s.AppendIntent(ctx, IntentInput{Mutation: withKey(withClient(as("github:alice"), chatgpt), "k1", "from claude"), WorkItemID: w.ID, Text: "from claude"})
	if err != nil {
		t.Fatal(err)
	}
	if created || replayed.ID != first.ID || replayed.ActorClientID != claude {
		t.Fatalf("replay = %+v (created=%v), want intent %d with client %q", replayed, created, first.ID, claude)
	}

	page, err := s.Intents(ctx, w.ID, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Intents) != 2 || page.Intents[0].ActorClientID != claude || page.Intents[1].ActorClientID != chatgpt {
		t.Fatalf("listed intents = %+v", page.Intents)
	}
	one, err := s.Intent(ctx, w.ID, strconv.FormatInt(second.ID, 10))
	if err != nil {
		t.Fatal(err)
	}
	if one.ActorClientID != chatgpt {
		t.Fatalf("single intent client = %q", one.ActorClientID)
	}

	// A retention sweep drops the text, never the provenance.
	if _, err := s.pool.Exec(ctx, `UPDATE work_item_intents SET text = NULL WHERE id = $1`, first.ID); err != nil {
		t.Fatal(err)
	}
	swept, err := s.Intent(ctx, w.ID, strconv.FormatInt(first.ID, 10))
	if err != nil {
		t.Fatal(err)
	}
	if !swept.TextRedacted || swept.ActorClientID != claude {
		t.Fatalf("swept intent = %+v, want redacted text with client %q", swept, claude)
	}

	events, err := s.Events(ctx, w.ID)
	if err != nil {
		t.Fatal(err)
	}
	clients := map[string][]string{}
	for _, e := range events {
		clients[e.Kind] = append(clients[e.Kind], e.ActorClientID)
	}
	if c := clients[EventCreated]; len(c) != 1 || c[0] != claude {
		t.Fatalf("created event clients = %v", c)
	}
	if c := clients[EventIntentAppended]; len(c) != 2 || c[0] != claude || c[1] != chatgpt {
		t.Fatalf("intent events clients = %v", c)
	}
}

func TestWorkItemWritesWithoutClientRecordEmpty(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	w := open(t, s, CreateInput{Mutation: as("svc:platform")})
	in, _, err := s.AppendIntent(ctx, IntentInput{Mutation: as("svc:platform"), WorkItemID: w.ID, Text: "no client"})
	if err != nil {
		t.Fatal(err)
	}
	if w.OriginClientID != "" || in.ActorClientID != "" {
		t.Fatalf("no-client writes recorded %q / %q", w.OriginClientID, in.ActorClientID)
	}
}
