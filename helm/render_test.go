// Package helm_test renders the mctl-api Helm chart with the real `helm`
// binary and asserts structurally on the output. Grep on the template text
// cannot tell "readOnly: true on the usage-pricing mount" from "readOnly:
// true somewhere in the file" -- several such flags already render -- so
// this shells out to `helm template` and unmarshals the result instead.
package helm_test

import (
	"bytes"
	"os"
	"os/exec"
	"path"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type secretKeyRef struct {
	Name     string `yaml:"name"`
	Key      string `yaml:"key"`
	Optional bool   `yaml:"optional"`
}

type envVarSource struct {
	SecretKeyRef *secretKeyRef `yaml:"secretKeyRef"`
}

type envVar struct {
	Name      string        `yaml:"name"`
	Value     string        `yaml:"value"`
	ValueFrom *envVarSource `yaml:"valueFrom"`
}

type volumeMount struct {
	Name      string `yaml:"name"`
	MountPath string `yaml:"mountPath"`
	ReadOnly  bool   `yaml:"readOnly"`
}

type configMapItem struct {
	Key  string `yaml:"key"`
	Path string `yaml:"path"`
}

type configMapVolumeSource struct {
	Name     string          `yaml:"name"`
	Optional bool            `yaml:"optional"`
	Items    []configMapItem `yaml:"items"`
}

type secretVolumeSource struct {
	SecretName  string `yaml:"secretName"`
	DefaultMode int    `yaml:"defaultMode"`
}

type volume struct {
	Name      string                 `yaml:"name"`
	ConfigMap *configMapVolumeSource `yaml:"configMap"`
	Secret    *secretVolumeSource    `yaml:"secret"`
}

type container struct {
	Name         string        `yaml:"name"`
	Env          []envVar      `yaml:"env"`
	VolumeMounts []volumeMount `yaml:"volumeMounts"`
}

type podSpec struct {
	Containers []container `yaml:"containers"`
	Volumes    []volume    `yaml:"volumes"`
}

type deployment struct {
	Spec struct {
		Template struct {
			Spec podSpec `yaml:"spec"`
		} `yaml:"template"`
	} `yaml:"spec"`
}

// requireHelm resolves the helm binary. When it is missing, the test is
// skipped locally (a developer without Helm installed is not blocked) but
// fails in CI (the assertion must not silently pass because the tool is
// absent).
func requireHelm(t *testing.T) string {
	t.Helper()
	helmPath, err := exec.LookPath("helm")
	if err != nil {
		if os.Getenv("CI") == "" {
			t.Skip("helm not found in PATH; skipping chart render test")
		}
		t.Fatalf("helm not found in PATH: %v", err)
	}
	return helmPath
}

func renderDeployment(t *testing.T, setArgs ...string) (deployment, []byte) {
	t.Helper()
	helmPath := requireHelm(t)

	args := []string{"template", "mctl-api", ".", "--show-only", "templates/deployment.yaml"}
	args = append(args, setArgs...)
	// #nosec G204 -- helmPath is resolved via exec.LookPath("helm") above, not
	// attacker input, and setArgs are fixed --set literals from this test's
	// own call sites, not external input.
	cmd := exec.Command(helmPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("helm template failed: %v\nstderr: %s", err, stderr.String())
	}

	var d deployment
	if err := yaml.Unmarshal(stdout.Bytes(), &d); err != nil {
		t.Fatalf("failed to unmarshal rendered deployment: %v\noutput:\n%s", err, stdout.String())
	}
	return d, stdout.Bytes()
}

func mainContainer(t *testing.T, d deployment) container {
	t.Helper()
	for _, c := range d.Spec.Template.Spec.Containers {
		if c.Name == "mctl-api" {
			return c
		}
	}
	t.Fatalf("mctl-api container not found in rendered deployment")
	return container{}
}

func findEnv(c container, name string) (envVar, bool) {
	for _, e := range c.Env {
		if e.Name == name {
			return e, true
		}
	}
	return envVar{}, false
}

func countEnv(c container, name string) int {
	n := 0
	for _, e := range c.Env {
		if e.Name == name {
			n++
		}
	}
	return n
}

func findVolumeMount(c container, name string) (volumeMount, bool) {
	for _, vm := range c.VolumeMounts {
		if vm.Name == name {
			return vm, true
		}
	}
	return volumeMount{}, false
}

func findVolume(d deployment, name string) (volume, bool) {
	for _, v := range d.Spec.Template.Spec.Volumes {
		if v.Name == name {
			return v, true
		}
	}
	return volume{}, false
}

func TestDeploymentDefaultRenderHasNoUsagePricing(t *testing.T) {
	d, _ := renderDeployment(t)
	c := mainContainer(t, d)

	if _, ok := findEnv(c, "USAGE_PRICING_CATALOG"); ok {
		t.Error("default render should not set USAGE_PRICING_CATALOG")
	}
	if _, ok := findVolumeMount(c, "usage-pricing"); ok {
		t.Error("default render should not mount usage-pricing")
	}
	if _, ok := findVolume(d, "usage-pricing"); ok {
		t.Error("default render should not have a usage-pricing volume")
	}
	if _, ok := findVolumeMount(c, "gitops-cache"); !ok {
		t.Error("expected gitops-cache mount to still be present")
	}
	if _, ok := findVolumeMount(c, "roadmap-state"); !ok {
		t.Error("expected roadmap-state mount to still be present")
	}
}

func TestDeploymentRendersUsagePricingEnvAndMount(t *testing.T) {
	d, _ := renderDeployment(t, "--set", "usagePricingConfigMap=mctl-api-usage-pricing")
	c := mainContainer(t, d)

	env, ok := findEnv(c, "USAGE_PRICING_CATALOG")
	if !ok {
		t.Fatal("expected USAGE_PRICING_CATALOG env to be rendered")
	}
	wantPath := "/etc/mctl-api/usage-pricing/catalog.json"
	if env.Value != wantPath {
		t.Errorf("USAGE_PRICING_CATALOG = %q, want %q", env.Value, wantPath)
	}

	mount, ok := findVolumeMount(c, "usage-pricing")
	if !ok {
		t.Fatal("expected usage-pricing volumeMount to be rendered")
	}
	// The mount path and the item path must agree with the env value so the
	// three literals can never drift apart silently.
	if mount.MountPath != path.Dir(wantPath) {
		t.Errorf("mountPath = %q, want %q", mount.MountPath, path.Dir(wantPath))
	}
	if !mount.ReadOnly {
		t.Error("expected usage-pricing mount to be readOnly")
	}

	vol, ok := findVolume(d, "usage-pricing")
	if !ok {
		t.Fatal("expected usage-pricing volume to be rendered")
	}
	if vol.ConfigMap == nil {
		t.Fatal("expected usage-pricing volume to have a configMap source")
	}
	if vol.ConfigMap.Name != "mctl-api-usage-pricing" {
		t.Errorf("configMap.name = %q, want %q", vol.ConfigMap.Name, "mctl-api-usage-pricing")
	}
	if !vol.ConfigMap.Optional {
		t.Error("expected configMap.optional to be true")
	}
	if len(vol.ConfigMap.Items) != 1 {
		t.Fatalf("expected exactly one configMap item, got %d", len(vol.ConfigMap.Items))
	}
	if vol.ConfigMap.Items[0].Path != path.Base(wantPath) {
		t.Errorf("item.path = %q, want %q", vol.ConfigMap.Items[0].Path, path.Base(wantPath))
	}
}

func TestDeploymentEmptyUsagePricingRendersUnchanged(t *testing.T) {
	_, defaultOut := renderDeployment(t)
	_, emptyOut := renderDeployment(t, "--set", "usagePricingConfigMap=")

	if !bytes.Equal(defaultOut, emptyOut) {
		t.Error("empty usagePricingConfigMap should render byte-identical output to the default")
	}
}

func TestDeploymentDefaultRenderHasNoSurfaceTelegramToken(t *testing.T) {
	d, _ := renderDeployment(t)
	c := mainContainer(t, d)

	if _, ok := findEnv(c, "MCTL_SURFACE_TELEGRAM_TOKEN"); ok {
		t.Error("default render should not set MCTL_SURFACE_TELEGRAM_TOKEN")
	}
}

func TestDeploymentEmptySurfaceTelegramTokenRendersUnchanged(t *testing.T) {
	_, defaultOut := renderDeployment(t)
	_, emptyOut := renderDeployment(t, "--set", "surfaceTelegramTokenSecret=")

	if !bytes.Equal(defaultOut, emptyOut) {
		t.Error("empty surfaceTelegramTokenSecret should render byte-identical output to the default")
	}
}

func TestDeploymentRendersSurfaceTelegramTokenEnv(t *testing.T) {
	d, _ := renderDeployment(t, "--set", "surfaceTelegramTokenSecret=mctl-api-surface-telegram")
	c := mainContainer(t, d)

	if n := countEnv(c, "MCTL_SURFACE_TELEGRAM_TOKEN"); n != 1 {
		t.Fatalf("expected exactly one MCTL_SURFACE_TELEGRAM_TOKEN env entry, got %d", n)
	}

	env, ok := findEnv(c, "MCTL_SURFACE_TELEGRAM_TOKEN")
	if !ok {
		t.Fatal("expected MCTL_SURFACE_TELEGRAM_TOKEN env to be rendered")
	}
	if env.Value != "" {
		t.Errorf("MCTL_SURFACE_TELEGRAM_TOKEN.value = %q, want empty (no literal leaked into the manifest)", env.Value)
	}
	if env.ValueFrom == nil || env.ValueFrom.SecretKeyRef == nil {
		t.Fatal("expected MCTL_SURFACE_TELEGRAM_TOKEN to be sourced from a secretKeyRef")
	}
	ref := env.ValueFrom.SecretKeyRef
	if ref.Name != "mctl-api-surface-telegram" {
		t.Errorf("secretKeyRef.name = %q, want %q", ref.Name, "mctl-api-surface-telegram")
	}
	if ref.Key != "MCTL_SURFACE_TELEGRAM_TOKEN" {
		t.Errorf("secretKeyRef.key = %q, want %q", ref.Key, "MCTL_SURFACE_TELEGRAM_TOKEN")
	}
	if !ref.Optional {
		t.Error("expected secretKeyRef.optional to be true")
	}
}

func TestDeploymentBothSurfaceTokenSecretsRenderIndependently(t *testing.T) {
	d, _ := renderDeployment(t,
		"--set", "usageWriterTokenSecret=mctl-api-usage-writer",
		"--set", "surfaceTelegramTokenSecret=mctl-api-surface-telegram",
	)
	c := mainContainer(t, d)

	usageEnv, ok := findEnv(c, "MCTL_USAGE_WRITER_TOKEN")
	if !ok {
		t.Fatal("expected MCTL_USAGE_WRITER_TOKEN env to be rendered")
	}
	if usageEnv.ValueFrom == nil || usageEnv.ValueFrom.SecretKeyRef == nil {
		t.Fatal("expected MCTL_USAGE_WRITER_TOKEN to be sourced from a secretKeyRef")
	}
	if got, want := usageEnv.ValueFrom.SecretKeyRef.Name, "mctl-api-usage-writer"; got != want {
		t.Errorf("MCTL_USAGE_WRITER_TOKEN secretKeyRef.name = %q, want %q", got, want)
	}
	if got, want := usageEnv.ValueFrom.SecretKeyRef.Key, "MCTL_USAGE_WRITER_TOKEN"; got != want {
		t.Errorf("MCTL_USAGE_WRITER_TOKEN secretKeyRef.key = %q, want %q", got, want)
	}

	telegramEnv, ok := findEnv(c, "MCTL_SURFACE_TELEGRAM_TOKEN")
	if !ok {
		t.Fatal("expected MCTL_SURFACE_TELEGRAM_TOKEN env to be rendered")
	}
	if telegramEnv.ValueFrom == nil || telegramEnv.ValueFrom.SecretKeyRef == nil {
		t.Fatal("expected MCTL_SURFACE_TELEGRAM_TOKEN to be sourced from a secretKeyRef")
	}
	if got, want := telegramEnv.ValueFrom.SecretKeyRef.Name, "mctl-api-surface-telegram"; got != want {
		t.Errorf("MCTL_SURFACE_TELEGRAM_TOKEN secretKeyRef.name = %q, want %q", got, want)
	}
	if got, want := telegramEnv.ValueFrom.SecretKeyRef.Key, "MCTL_SURFACE_TELEGRAM_TOKEN"; got != want {
		t.Errorf("MCTL_SURFACE_TELEGRAM_TOKEN secretKeyRef.key = %q, want %q", got, want)
	}
}

func TestDeploymentDefaultRenderKeepsOIDCProvidersLiteral(t *testing.T) {
	d, _ := renderDeployment(t)
	c := mainContainer(t, d)

	// The empty default from values.yaml env, as before oidcProvidersSecret.
	if n := countEnv(c, "MCTL_OIDC_PROVIDERS"); n != 1 {
		t.Fatalf("expected exactly one MCTL_OIDC_PROVIDERS env entry, got %d", n)
	}
	env, _ := findEnv(c, "MCTL_OIDC_PROVIDERS")
	if env.Value != "" || env.ValueFrom != nil {
		t.Errorf("default MCTL_OIDC_PROVIDERS = %+v, want an empty literal", env)
	}
}

func TestDeploymentEmptyOIDCProvidersRendersUnchanged(t *testing.T) {
	_, defaultOut := renderDeployment(t)
	_, emptyOut := renderDeployment(t, "--set", "oidcProvidersSecret=")

	if !bytes.Equal(defaultOut, emptyOut) {
		t.Error("empty oidcProvidersSecret should render byte-identical output to the default")
	}
}

func TestDeploymentRendersOIDCProvidersEnv(t *testing.T) {
	d, _ := renderDeployment(t, "--set", "oidcProvidersSecret=mctl-api-oidc-zitadel")
	c := mainContainer(t, d)

	if n := countEnv(c, "MCTL_OIDC_PROVIDERS"); n != 1 {
		t.Fatalf("expected exactly one MCTL_OIDC_PROVIDERS env entry, got %d", n)
	}
	env, _ := findEnv(c, "MCTL_OIDC_PROVIDERS")
	if env.Value != "" {
		t.Errorf("MCTL_OIDC_PROVIDERS.value = %q, want empty (sourced from the Secret only)", env.Value)
	}
	if env.ValueFrom == nil || env.ValueFrom.SecretKeyRef == nil {
		t.Fatal("expected MCTL_OIDC_PROVIDERS to be sourced from a secretKeyRef")
	}
	ref := env.ValueFrom.SecretKeyRef
	if ref.Name != "mctl-api-oidc-zitadel" {
		t.Errorf("secretKeyRef.name = %q, want %q", ref.Name, "mctl-api-oidc-zitadel")
	}
	if ref.Key != "MCTL_OIDC_PROVIDERS" {
		t.Errorf("secretKeyRef.key = %q, want %q", ref.Key, "MCTL_OIDC_PROVIDERS")
	}
	// The Job fills the Secret after Argo CD creates it empty: a required
	// reference would hold the pod in CreateContainerConfigError until then.
	if !ref.Optional {
		t.Error("expected secretKeyRef.optional to be true")
	}
}

func TestDeploymentOIDCProvidersSecretConflictsWithLiteral(t *testing.T) {
	helmPath := requireHelm(t)

	// #nosec G204 -- helmPath is resolved via exec.LookPath("helm"), and the
	// arguments are fixed literals.
	cmd := exec.Command(helmPath, "template", "mctl-api", ".",
		"--set", "oidcProvidersSecret=mctl-api-oidc-zitadel",
		"--set-string", "env.MCTL_OIDC_PROVIDERS=[]",
	)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err == nil {
		t.Fatal("expected helm template to fail when both env.MCTL_OIDC_PROVIDERS and oidcProvidersSecret are set")
	}
	if !strings.Contains(out.String(), "not both") {
		t.Errorf("unexpected failure output:\n%s", out.String())
	}
}

func TestDeploymentEmptyZitadelLinkSecretRendersUnchanged(t *testing.T) {
	_, defaultOut := renderDeployment(t)
	_, emptyOut := renderDeployment(t, "--set", "zitadelLinkSecret=")

	if !bytes.Equal(defaultOut, emptyOut) {
		t.Error("empty zitadelLinkSecret should render byte-identical output to the default")
	}
}

func TestDeploymentRendersZitadelLinkSecretEnv(t *testing.T) {
	d, _ := renderDeployment(t, "--set", "zitadelLinkSecret=mctl-api-oidc-zitadel")
	c := mainContainer(t, d)

	for _, name := range []string{"ZITADEL_LINK_CLIENT_ID", "ZITADEL_LINK_CLIENT_SECRET"} {
		if n := countEnv(c, name); n != 1 {
			t.Fatalf("expected exactly one %s env entry, got %d", name, n)
		}
		env, _ := findEnv(c, name)
		if env.Value != "" {
			t.Errorf("%s.value = %q, want empty (no literal in the manifest)", name, env.Value)
		}
		if env.ValueFrom == nil || env.ValueFrom.SecretKeyRef == nil {
			t.Fatalf("expected %s to be sourced from a secretKeyRef", name)
		}
		ref := env.ValueFrom.SecretKeyRef
		if ref.Name != "mctl-api-oidc-zitadel" || ref.Key != name {
			t.Errorf("%s secretKeyRef = %s/%s, want mctl-api-oidc-zitadel/%s", name, ref.Name, ref.Key, name)
		}
		if !ref.Optional {
			t.Errorf("expected %s secretKeyRef.optional to be true", name)
		}
	}
}

func TestDeploymentUsagePricingKeyOverride(t *testing.T) {
	d, _ := renderDeployment(t,
		"--set", "usagePricingConfigMap=cm",
		"--set", "usagePricingConfigMapKey=rates.json",
	)

	vol, ok := findVolume(d, "usage-pricing")
	if !ok {
		t.Fatal("expected usage-pricing volume to be rendered")
	}
	if vol.ConfigMap == nil || len(vol.ConfigMap.Items) != 1 {
		t.Fatal("expected exactly one configMap item")
	}
	item := vol.ConfigMap.Items[0]
	if item.Key != "rates.json" {
		t.Errorf("item.key = %q, want %q", item.Key, "rates.json")
	}
	// The mounted file name must stay catalog.json regardless of the source
	// key, so the env value template constant never has to change.
	if item.Path != "catalog.json" {
		t.Errorf("item.path = %q, want %q", item.Path, "catalog.json")
	}

	c := mainContainer(t, d)
	env, ok := findEnv(c, "USAGE_PRICING_CATALOG")
	if !ok || env.Value != "/etc/mctl-api/usage-pricing/catalog.json" {
		t.Errorf("USAGE_PRICING_CATALOG unexpectedly changed: %+v", env)
	}
}

func TestDeploymentUsagePricingLeavesOtherVolumesIntact(t *testing.T) {
	d, _ := renderDeployment(t,
		"--set", "usagePricingConfigMap=mctl-api-usage-pricing",
		"--set", "githubAppTokenSecret=s",
		"--set", "postgresCA.secretName=ca",
	)
	c := mainContainer(t, d)

	ghMount, ok := findVolumeMount(c, "github-app-token")
	if !ok || !ghMount.ReadOnly {
		t.Error("expected github-app-token mount to still be present and readOnly")
	}
	ghVol, ok := findVolume(d, "github-app-token")
	if !ok || ghVol.Secret == nil {
		t.Fatal("expected github-app-token volume to still be present")
	}
	if ghVol.Secret.DefaultMode != 0444 {
		t.Errorf("github-app-token defaultMode = %o, want %o", ghVol.Secret.DefaultMode, 0444)
	}

	caMount, ok := findVolumeMount(c, "cnpg-ca")
	if !ok || !caMount.ReadOnly {
		t.Error("expected cnpg-ca mount to still be present and readOnly")
	}
	caVol, ok := findVolume(d, "cnpg-ca")
	if !ok || caVol.Secret == nil {
		t.Fatal("expected cnpg-ca volume to still be present")
	}
	if caVol.Secret.DefaultMode != 0444 {
		t.Errorf("cnpg-ca defaultMode = %o, want %o", caVol.Secret.DefaultMode, 0444)
	}
}

func TestHelmLintCleanAcrossOptionalValues(t *testing.T) {
	helmPath := requireHelm(t)

	cases := [][]string{
		nil,
		{"--set", "usagePricingConfigMap=mctl-api-usage-pricing"},
		{"--set", "surfaceTelegramTokenSecret=mctl-api-surface-telegram"},
		{"--set", "oidcProvidersSecret=mctl-api-oidc-zitadel"},
		{"--set", "zitadelLinkSecret=mctl-api-oidc-zitadel"},
	}
	for _, extra := range cases {
		args := append([]string{"lint", "."}, extra...)
		// #nosec G204 -- helmPath is resolved via exec.LookPath("helm") above,
		// not attacker input, and extra is a fixed literal from the cases
		// slice defined a few lines above, not external input.
		cmd := exec.Command(helmPath, args...)
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &out
		if err := cmd.Run(); err != nil {
			t.Errorf("helm lint . %v failed: %v\n%s", extra, err, out.String())
		}
	}
}
