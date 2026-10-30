package deployplan

import (
	"errors"
	"strings"
	"testing"
)

// T1 (package part): schema-invalid intents are refused, never trimmed.
func TestParseIntent_SchemaInvalid(t *testing.T) {
	good := string(testIntentJSON("acme", "web", ""))
	for name, raw := range map[string]string{
		"extraObjects at top level": strings.Replace(good, `"kind":"DeployIntent",`, `"kind":"DeployIntent","extraObjects":[{}],`, 1),
		"extraObjects under spec":   strings.Replace(good, `"exposure":`, `"extraObjects":[{}],"exposure":`, 1),
		"unknown nested key":        strings.Replace(good, `"detection":{"tier":"tier0"}`, `"detection":{"tier":"tier0","x":1}`, 1),
		"duplicate key":             strings.Replace(good, `"kind":"DeployIntent",`, `"kind":"DeployIntent","kind":"DeployIntent",`, 1),
		"trailing data":             good + `{}`,
		"not json":                  `nope`,
		"revision is a branch":      strings.Replace(good, testRev, "main", 1),
	} {
		_, _, err := ParseIntent([]byte(raw))
		if !errors.Is(err, ErrIntentInvalid) {
			t.Errorf("%s: err = %v, want ErrIntentInvalid", name, err)
		}
	}
}

// T4: omitted and explicit defaults canonicalize identically; key order is
// irrelevant; the canonical bytes are stable.
func TestParseIntent_CanonicalIsStableAndDefaultsExplicit(t *testing.T) {
	omitted := testIntentJSON("acme", "web", "")
	explicit := []byte(strings.Replace(string(omitted),
		`"source":{`, `"source":{"dockerfile":"Dockerfile","context":".",`, 1))
	explicit = []byte(strings.Replace(string(explicit), `"healthPath":"/healthz"`, `"healthPath":"/healthz","replicas":1`, 1))
	reordered := []byte(`{"spec":{"exposure":{"mode":"public"},"runtime":{"healthPath":"/healthz","port":8080},` +
		`"detection":{"tier":"tier0"},"source":{"revision":"` + testRev + `","repository":"acme/web"},"environment":"preview"},` +
		`"metadata":{"service":"web","tenant":"acme"},"kind":"DeployIntent","apiVersion":"deploy.mctl.ai/v1alpha1"}`)

	_, a := mustParse(t, omitted)
	_, b := mustParse(t, explicit)
	_, c := mustParse(t, reordered)
	if string(a) != string(b) || string(a) != string(c) {
		t.Fatalf("canonical forms differ:\n%s\n%s\n%s", a, b, c)
	}
	for _, want := range []string{`"dockerfile":"Dockerfile"`, `"context":"."`, `"replicas":1`} {
		if !strings.Contains(string(a), want) {
			t.Errorf("canonical intent lacks default %s: %s", want, a)
		}
	}
	_, again := mustParse(t, omitted)
	if string(again) != string(a) {
		t.Error("canonical JSON is not byte-stable")
	}
	in, _ := mustParse(t, omitted)
	if da, db := digestOf(t, in, a), digestOf(t, in, b); da != db {
		t.Errorf("digests differ: %s %s", da, db)
	}
}

func digestOf(t *testing.T, in Intent, canon []byte) string {
	t.Helper()
	return Digest(DigestInput{
		Tenant: in.Metadata.Tenant, Service: in.Metadata.Service, Environment: in.Spec.Environment,
		IntentCanonical: string(canon), Revision: in.Spec.Source.Revision, GitopsBaseSHA: testRev,
		Action: ActionUpdate, PreviewID: "abc123", ValuesAfter: "a: 1\n", Host: "web-abc123.mctl.ai",
	})
}
