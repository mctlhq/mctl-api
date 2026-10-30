package deployplan

import (
	"encoding/json"
	"testing"
)

const testRev = "0123456789abcdef0123456789abcdef01234567"

// testIntentJSON is a schema-valid preview intent; extra is spliced into spec.
func testIntentJSON(tenant, service, extra string) []byte {
	return []byte(`{"apiVersion":"deploy.mctl.ai/v1alpha1","kind":"DeployIntent",` +
		`"metadata":{"tenant":"` + tenant + `","service":"` + service + `"},` +
		`"spec":{"environment":"preview","source":{"repository":"acme/` + service + `","revision":"` + testRev + `"},` +
		`"detection":{"tier":"tier0"},"runtime":{"port":8080,"healthPath":"/healthz"},"exposure":{"mode":"public"}` + extra + `}}`)
}

func mustParse(t *testing.T, raw []byte) (Intent, []byte) {
	t.Helper()
	in, canon, err := ParseIntent(raw)
	if err != nil {
		t.Fatalf("ParseIntent: %v\n%s", err, raw)
	}
	return in, canon
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
