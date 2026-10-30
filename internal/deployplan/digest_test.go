package deployplan

import (
	"reflect"
	"strings"
	"testing"
)

func baseDigestInput() DigestInput {
	return DigestInput{
		Tenant: "acme", Service: "web", Environment: "preview", IntentCanonical: `{"a":1}`,
		Revision: testRev, GitopsBaseSHA: strings.Repeat("b", 40), Action: ActionUpdate,
		PreviewID: "abc123", ValuesAfter: "x: 1\n", Host: "web-abc123.mctl.ai",
	}
}

// T3: stable, and sensitive to every bound field.
func TestDigest_StableAndSensitive(t *testing.T) {
	base := baseDigestInput()
	d := Digest(base)
	if !strings.HasPrefix(d, "sha256:") || len(d) != len("sha256:")+64 {
		t.Fatalf("digest shape: %s", d)
	}
	if Digest(base) != d {
		t.Fatal("same input, different digest")
	}
	mutations := map[string]func(*DigestInput){
		"tenant":           func(i *DigestInput) { i.Tenant = "acme2" },
		"service":          func(i *DigestInput) { i.Service = "web2" },
		"environment":      func(i *DigestInput) { i.Environment = "production" },
		"canonical_intent": func(i *DigestInput) { i.IntentCanonical = `{"a":2}` },
		"revision":         func(i *DigestInput) { i.Revision = strings.Repeat("c", 40) },
		"gitops_base_sha":  func(i *DigestInput) { i.GitopsBaseSHA = strings.Repeat("d", 40) },
		"action":           func(i *DigestInput) { i.Action = ActionOnboard },
		"preview_id":       func(i *DigestInput) { i.PreviewID = "zzzzzz" },
		"values_after":     func(i *DigestInput) { i.ValuesAfter = "x: 2\n" },
		"host":             func(i *DigestInput) { i.Host = "other.mctl.ai" },
	}
	for name, mutate := range mutations {
		m := base
		mutate(&m)
		if Digest(m) == d {
			t.Errorf("changing %s did not change the digest", name)
		}
	}
	// Length prefixes: moving a byte across a field boundary must change it.
	a, b := base, base
	a.Tenant, a.Service = "ab", "c"
	b.Tenant, b.Service = "a", "bc"
	if Digest(a) == Digest(b) {
		t.Error("field boundaries are not bound")
	}
}

func TestDigest_EncodingVersionPrefix(t *testing.T) {
	if encodingVersion != "mctl-deploy-plan/v1" || SchemaVersion != encodingVersion {
		t.Fatalf("encoding version = %q", encodingVersion)
	}
}

// The plan metadata is not part of the digest by construction: DigestInput
// has no field for id, timestamps, expiry, idempotency key or caller.
func TestDigestInput_HasNoPlanMetadata(t *testing.T) {
	typ := reflect.TypeOf(DigestInput{})
	want := []string{"Tenant", "Service", "Environment", "IntentCanonical", "Revision", "GitopsBaseSHA", "Action", "PreviewID", "ValuesAfter", "Host"}
	if typ.NumField() != len(want) {
		t.Fatalf("DigestInput has %d fields, want exactly %d", typ.NumField(), len(want))
	}
	for i, name := range want {
		if typ.Field(i).Name != name {
			t.Errorf("field %d = %s, want %s (the order is the documented encoding order)", i, typ.Field(i).Name, name)
		}
	}
}
