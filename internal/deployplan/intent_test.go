package deployplan

import (
	"bytes"
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
	if !bytes.Equal(a, b) || !bytes.Equal(a, c) {
		t.Fatalf("canonical forms differ:\n%s\n%s\n%s", a, b, c)
	}
	for _, want := range []string{`"dockerfile":"Dockerfile"`, `"context":"."`, `"replicas":1`} {
		if !strings.Contains(string(a), want) {
			t.Errorf("canonical intent lacks default %s: %s", want, a)
		}
	}
	_, again := mustParse(t, omitted)
	if !bytes.Equal(again, a) {
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

// mctl-api#1118: runtime.port is the port the container binds, so the floor
// of 1024 stays; runtime.servicePort is the Service port and may be any
// valid port, privileged ones included.
func TestParseIntent_Ports(t *testing.T) {
	good := string(testIntentJSON("acme", "web", ""))
	withRuntime := func(rt string) []byte {
		return []byte(strings.Replace(good, `"runtime":{"port":8080,"healthPath":"/healthz"}`, `"runtime":`+rt, 1))
	}
	for name, rt := range map[string]string{
		"privileged container port": `{"port":80,"healthPath":"/healthz"}`,
		"container port 1023":       `{"port":1023,"healthPath":"/healthz"}`,
		"service port 0":            `{"port":8080,"servicePort":0,"healthPath":"/healthz"}`,
		"service port above 65535":  `{"port":8080,"servicePort":65536,"healthPath":"/healthz"}`,
		"service port as a string":  `{"port":8080,"servicePort":"80","healthPath":"/healthz"}`,
	} {
		if _, _, err := ParseIntent(withRuntime(rt)); !errors.Is(err, ErrIntentInvalid) {
			t.Errorf("%s: err = %v, want ErrIntentInvalid", name, err)
		}
	}
	in, canon := mustParse(t, withRuntime(`{"port":8080,"servicePort":80,"healthPath":"/healthz"}`))
	if in.Spec.Runtime.Port != 8080 || in.Spec.Runtime.ServicePort != 80 {
		t.Fatalf("runtime = %+v", in.Spec.Runtime)
	}
	if !strings.Contains(string(canon), `"servicePort":80`) {
		t.Fatalf("canonical intent lacks servicePort: %s", canon)
	}
	// An intent without servicePort canonicalizes as before the field
	// existed, so stored plans keep their digests.
	if _, c := mustParse(t, []byte(good)); strings.Contains(string(c), "servicePort") {
		t.Fatalf("absent servicePort leaked into the canonical intent: %s", c)
	}
}
