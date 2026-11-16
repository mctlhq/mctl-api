package deployplan

import (
	"errors"
	"testing"
)

// chartDefaults is the part of base-service's values.yaml the change check
// depends on (mctl-gitops platform-gitops/helm-charts/base-service).
const chartDefaults = `
service:
  type: ClusterIP
  port: 8080
replicaCount: 1
probes:
  liveness:
    path: /healthz
    port: http
  readiness:
    path: /readyz
    port: http
resources:
  requests:
    cpu: 50m
    memory: 64Mi
env: {}
envFrom: []
`

func runtimeIntent(runtime, extra string) []byte {
	return []byte(`{"apiVersion":"deploy.mctl.ai/v1alpha1","kind":"DeployIntent",` +
		`"metadata":{"tenant":"acme","service":"web"},` +
		`"spec":{"environment":"preview","source":{"repository":"acme/web","revision":"` + testRev + `"},` +
		`"detection":{"tier":"tier0"},"runtime":` + runtime + `,"exposure":{"mode":"public"}` + extra + `}}`)
}

const explicitProbes = `
image:
  tag: 1.0.0
service:
  port: 8080
probes:
  liveness:
    path: /healthz
  readiness:
    path: /healthz
`

// mctl-api#1058: an intent that writes only what the chart already renders
// is not a change; anything the render would show still is.
func TestChangesRender(t *testing.T) {
	healthz := `{"port":8080,"healthPath":"/healthz"}`
	for name, tc := range map[string]struct {
		base, runtime, extra string
		want                 bool
	}{
		// The coolify-mcp case: values differ only by replicaCount: 1.
		"implicit replicaCount equals chart default": {explicitProbes, healthz, "", false},
		"implicit port equals chart default": {`
probes:
  liveness: {path: /healthz}
  readiness: {path: /healthz}
`, healthz, "", false},
		"port missing inside a service map": {`
service:
  type: ClusterIP
probes:
  liveness: {path: /healthz}
  readiness: {path: /healthz}
`, healthz, "", false},
		"explicit everything":               {explicitProbes + "replicaCount: 1\n", healthz, "", false},
		"readiness default differs":         {"service:\n  port: 8080\n", healthz, "", true},
		"port differs from chart":           {explicitProbes, `{"port":3000,"healthPath":"/healthz"}`, "", true},
		"port differs from values":          {explicitProbes, `{"port":9090,"healthPath":"/healthz"}`, "", true},
		"health path differs":               {explicitProbes, `{"port":8080,"healthPath":"/ready"}`, "", true},
		"replicas differ from chart":        {explicitProbes, `{"port":8080,"healthPath":"/healthz","replicas":2}`, "", true},
		"replicas differ from values":       {explicitProbes + "replicaCount: 3\n", healthz, "", true},
		"null in values is not the default": {explicitProbes + "replicaCount: null\n", healthz, "", true},
		"env added":                         {explicitProbes, healthz, `,"env":{"FEATURE":"on"}`, true},
		"env equal to values":               {explicitProbes + "env:\n  FEATURE: \"on\"\n", healthz, `,"env":{"FEATURE":"on"}`, false},
		"secret ref added":                  {explicitProbes, healthz, `,"secretRefs":[{"env":"DB_PASSWORD","property":"password"}]`, true},
	} {
		t.Run(name, func(t *testing.T) {
			in, _ := mustParse(t, runtimeIntent(tc.runtime, tc.extra))
			before, after, err := CompilePreview([]byte(tc.base), in, "ab12cd", "web-ab12cd.mctl.ai")
			if err != nil {
				t.Fatal(err)
			}
			got, err := ChangesRender([]byte(chartDefaults), before, after)
			if err != nil || got != tc.want {
				t.Fatalf("ChangesRender = %v, %v; want %v", got, err, tc.want)
			}
		})
	}
}

// Defaults that cannot be used are an error, never an empty layer.
func TestChangesRenderRefusesUnusableDefaults(t *testing.T) {
	in, _ := mustParse(t, runtimeIntent(`{"port":8080,"healthPath":"/healthz"}`, ""))
	before, after, err := CompilePreview([]byte(explicitProbes), in, "ab12cd", "web-ab12cd.mctl.ai")
	if err != nil {
		t.Fatal(err)
	}
	for name, d := range map[string]string{
		"empty": "", "null": "null\n", "empty mapping": "{}\n", "list": "- a\n", "unparseable": "a: [\n",
	} {
		if _, err := ChangesRender([]byte(d), before, after); !errors.Is(err, ErrChartDefaultsUnusable) {
			t.Errorf("%s: err = %v, want ErrChartDefaultsUnusable", name, err)
		}
	}
}

// The comparison must not write into the plan's values.
func TestChangesRenderLeavesInputsAlone(t *testing.T) {
	in, _ := mustParse(t, runtimeIntent(`{"port":8080,"healthPath":"/healthz"}`, ""))
	before, after, err := CompilePreview([]byte(explicitProbes), in, "ab12cd", "web-ab12cd.mctl.ai")
	if err != nil {
		t.Fatal(err)
	}
	bYAML, _ := RenderYAML(before)
	aYAML, _ := RenderYAML(after)
	if _, err := ChangesRender([]byte(chartDefaults), before, after); err != nil {
		t.Fatal(err)
	}
	if b, _ := RenderYAML(before); b != bYAML {
		t.Errorf("before changed:\n%s", b)
	}
	if a, _ := RenderYAML(after); a != aYAML {
		t.Errorf("after changed:\n%s", a)
	}
}
