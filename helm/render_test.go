// Package helm_test renders the mctl-api Helm chart with the real `helm`
// binary and asserts structurally on the output. Grep on the template text
// cannot tell "readOnly: true on the usage-pricing mount" from "readOnly:
// true somewhere in the file" -- several such flags already render -- so
// this shells out to `helm template` and unmarshals the result instead.
package helm_test

import (
	"bytes"
	"encoding/json"
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

type secretEnvSource struct {
	Name     string `yaml:"name"`
	Optional bool   `yaml:"optional"`
}

type envFromSource struct {
	SecretRef *secretEnvSource `yaml:"secretRef"`
}

type container struct {
	Name         string          `yaml:"name"`
	EnvFrom      []envFromSource `yaml:"envFrom"`
	Env          []envVar        `yaml:"env"`
	VolumeMounts []volumeMount   `yaml:"volumeMounts"`
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

func TestDeploymentDefaultRenderHasNoSecurityProviders(t *testing.T) {
	d, _ := renderDeployment(t)
	c := mainContainer(t, d)

	for _, name := range []string{"SECURITY_PROVIDERS", "MCTL_SECURITY_PROVIDER_TOKENS"} {
		if _, ok := findEnv(c, name); ok {
			t.Errorf("default render should not set %s", name)
		}
	}
}

func TestDeploymentEmptySecurityProviderValuesRenderUnchanged(t *testing.T) {
	_, defaultOut := renderDeployment(t)
	_, emptyOut := renderDeployment(t, "--set", "securityProviderTokensSecret=")

	if !bytes.Equal(defaultOut, emptyOut) {
		t.Error("empty securityProviderTokensSecret should render byte-identical output to the default")
	}
}

func TestDeploymentRendersSecurityProviders(t *testing.T) {
	d, _ := renderDeployment(t,
		"--set", "securityProviders[0].ref=trivy",
		"--set", "securityProviders[0].max_strength=scanner_rerun_exact_revision",
		"--set", "securityProviders[0].tenants[0]=admins",
		"--set", "securityProviderTokensSecret=mctl-api-security-providers",
	)
	c := mainContainer(t, d)

	cfg, ok := findEnv(c, "SECURITY_PROVIDERS")
	if !ok {
		t.Fatal("expected SECURITY_PROVIDERS env to be rendered")
	}
	var providers []struct {
		Ref         string   `json:"ref"`
		MaxStrength string   `json:"max_strength"`
		Tenants     []string `json:"tenants"`
	}
	if err := json.Unmarshal([]byte(cfg.Value), &providers); err != nil {
		t.Fatalf("SECURITY_PROVIDERS is not JSON: %v (%q)", err, cfg.Value)
	}
	if len(providers) != 1 || providers[0].Ref != "trivy" || providers[0].MaxStrength != "scanner_rerun_exact_revision" ||
		len(providers[0].Tenants) != 1 || providers[0].Tenants[0] != "admins" {
		t.Errorf("SECURITY_PROVIDERS = %+v", providers)
	}

	tokens, ok := findEnv(c, "MCTL_SECURITY_PROVIDER_TOKENS")
	if !ok {
		t.Fatal("expected MCTL_SECURITY_PROVIDER_TOKENS env to be rendered")
	}
	if tokens.Value != "" || tokens.ValueFrom == nil || tokens.ValueFrom.SecretKeyRef == nil {
		t.Fatalf("MCTL_SECURITY_PROVIDER_TOKENS must come from a secretKeyRef only: %+v", tokens)
	}
	ref := tokens.ValueFrom.SecretKeyRef
	if ref.Name != "mctl-api-security-providers" || ref.Key != "MCTL_SECURITY_PROVIDER_TOKENS" || !ref.Optional {
		t.Errorf("secretKeyRef = %+v", ref)
	}
}

func TestDeploymentRendersSecurityCodeScanning(t *testing.T) {
	d, _ := renderDeployment(t)
	if _, ok := findEnv(mainContainer(t, d), "SECURITY_GITHUB_CODE_SCANNING"); ok {
		t.Error("default render should not set SECURITY_GITHUB_CODE_SCANNING")
	}
	d, _ = renderDeployment(t,
		"--set", "securityCodeScanning.repositories.mctlhq/mctl-api=admins",
		"--set", "securityCodeScanning.tools[0]=Trivy",
		"--set", "securityCodeScanning.actions[0]=created",
	)
	env, ok := findEnv(mainContainer(t, d), "SECURITY_GITHUB_CODE_SCANNING")
	if !ok {
		t.Fatal("expected SECURITY_GITHUB_CODE_SCANNING env")
	}
	var cfg struct {
		Repositories map[string]string `json:"repositories"`
		Tools        []string          `json:"tools"`
		Actions      []string          `json:"actions"`
	}
	if err := json.Unmarshal([]byte(env.Value), &cfg); err != nil {
		t.Fatalf("not JSON: %v (%q)", err, env.Value)
	}
	if cfg.Repositories["mctlhq/mctl-api"] != "admins" || len(cfg.Tools) != 1 || len(cfg.Actions) != 1 {
		t.Errorf("config = %+v", cfg)
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

func TestDeploymentZitadelLinkSecretConflictsWithLiteral(t *testing.T) {
	helmPath := requireHelm(t)

	for _, key := range []string{"ZITADEL_LINK_CLIENT_ID", "ZITADEL_LINK_CLIENT_SECRET"} {
		// #nosec G204 -- helmPath is resolved via exec.LookPath("helm"), and the
		// arguments are fixed literals.
		cmd := exec.Command(helmPath, "template", "mctl-api", ".",
			"--set", "zitadelLinkSecret=mctl-api-oidc-zitadel",
			"--set-string", "env."+key+"=literal",
		)
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &out
		if err := cmd.Run(); err == nil {
			t.Fatalf("expected helm template to fail when both env.%s and zitadelLinkSecret are set", key)
		}
		if !strings.Contains(out.String(), "not both") {
			t.Errorf("%s: unexpected failure output:\n%s", key, out.String())
		}
	}
}

// An empty literal does not trip the guard, but must not render a second
// entry next to the secretKeyRef either.
func TestDeploymentZitadelLinkSecretSkipsAnEmptyLiteral(t *testing.T) {
	d, _ := renderDeployment(t, "--set", "zitadelLinkSecret=mctl-api-oidc-zitadel",
		"--set-string", "env.ZITADEL_LINK_CLIENT_ID=")
	n := 0
	for _, e := range d.Spec.Template.Spec.Containers[0].Env {
		if e.Name == "ZITADEL_LINK_CLIENT_ID" {
			n++
			if e.ValueFrom == nil || e.ValueFrom.SecretKeyRef == nil {
				t.Errorf("ZITADEL_LINK_CLIENT_ID rendered as a literal: %+v", e)
			}
		}
	}
	if n != 1 {
		t.Errorf("ZITADEL_LINK_CLIENT_ID rendered %d times, want 1", n)
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

// oauthZitadelSecret (mctl-api#467) and devLoopDecideSecret (mctl-api#964)
// follow zitadelLinkSecret exactly: one secretKeyRef per key, optional,
// refused next to a literal, and inert when empty.
func TestDeploymentOAuthZitadelSecret(t *testing.T) {
	testClientSecretValue(t, "oauthZitadelSecret", "OAUTH_ZITADEL_CLIENT_ID", "OAUTH_ZITADEL_CLIENT_SECRET")
}

func TestDeploymentDevLoopDecideSecret(t *testing.T) {
	testClientSecretValue(t, "devLoopDecideSecret", "DEVLOOP_DECIDE_CLIENT_ID", "DEVLOOP_DECIDE_CLIENT_SECRET")
}

func testClientSecretValue(t *testing.T, value, idKey, secretKey string) {
	t.Helper()
	helmPath := requireHelm(t)
	for _, key := range []string{idKey, secretKey} {
		// #nosec G204 -- helmPath is resolved via exec.LookPath("helm"), and the
		// arguments are fixed literals.
		cmd := exec.Command(helmPath, "template", "mctl-api", ".",
			"--set", value+"=mctl-api-oidc-zitadel",
			"--set-string", "env."+key+"=literal",
		)
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &out
		if err := cmd.Run(); err == nil || !strings.Contains(out.String(), "not both") {
			t.Errorf("%s: want a 'not both' failure next to %s, got err=%v\n%s", key, value, err, out.String())
		}
	}

	_, defaultOut := renderDeployment(t)
	_, emptyOut := renderDeployment(t, "--set", value+"=")
	if !bytes.Equal(defaultOut, emptyOut) {
		t.Errorf("empty %s should render byte-identical output to the default", value)
	}

	d, _ := renderDeployment(t, "--set", value+"=mctl-api-oidc-zitadel",
		"--set-string", "env."+idKey+"=")
	c := mainContainer(t, d)
	for _, name := range []string{idKey, secretKey} {
		if n := countEnv(c, name); n != 1 {
			t.Fatalf("expected exactly one %s env entry, got %d", name, n)
		}
		env, _ := findEnv(c, name)
		if env.Value != "" || env.ValueFrom == nil || env.ValueFrom.SecretKeyRef == nil {
			t.Fatalf("%s = %+v, want a secretKeyRef and no literal", name, env)
		}
		ref := env.ValueFrom.SecretKeyRef
		if ref.Name != "mctl-api-oidc-zitadel" || ref.Key != name || !ref.Optional {
			t.Errorf("%s secretKeyRef = %s/%s optional=%v, want mctl-api-oidc-zitadel/%s optional", name, ref.Name, ref.Key, ref.Optional, name)
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
		{"--set", "oauthZitadelSecret=mctl-api-oidc-zitadel"},
		{"--set", "devLoopDecideSecret=mctl-api-oidc-zitadel"},
		{"--set", "envFromOptionalSecrets={mctl-api-zitadel-hook}"},
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

// The identity-link browser flow lives under /identity (mctlhq/mctl-api#435);
// without the path Traefik answers 404 before the request reaches mctl-api.
// Both the values.yaml list and the template's fallback (paths unset) must
// carry it.
func TestIngressRoutesIdentityLinkPath(t *testing.T) {
	helmPath := requireHelm(t)
	for name, setArgs := range map[string][]string{
		"values.yaml paths": nil,
		"template fallback": {"--set", "ingress.paths=null"},
	} {
		t.Run(name, func(t *testing.T) {
			args := append([]string{"template", "mctl-api", ".", "--show-only", "templates/ingress.yaml"}, setArgs...)
			// #nosec G204 -- helmPath comes from exec.LookPath("helm"); args are literals.
			out, err := exec.Command(helmPath, args...).CombinedOutput()
			if err != nil {
				t.Fatalf("helm template failed: %v\n%s", err, out)
			}
			var ing struct {
				Spec struct {
					Rules []struct {
						Host string `yaml:"host"`
						HTTP struct {
							Paths []struct {
								Path string `yaml:"path"`
							} `yaml:"paths"`
						} `yaml:"http"`
					} `yaml:"rules"`
				} `yaml:"spec"`
			}
			if err := yaml.Unmarshal(out, &ing); err != nil {
				t.Fatalf("unmarshal ingress: %v\n%s", err, out)
			}
			if len(ing.Spec.Rules) == 0 {
				t.Fatalf("no ingress rules rendered:\n%s", out)
			}
			// /devloop: the DevLoop decide page (mctlhq/mctl-api#964).
			for _, want := range []string{"/identity", "/devloop"} {
				for _, r := range ing.Spec.Rules {
					found := false
					for _, p := range r.HTTP.Paths {
						found = found || p.Path == want
					}
					if !found {
						t.Errorf("host %s has no %s path", r.Host, want)
					}
				}
			}
		})
	}
}

// envFromOptionalSecrets adds envFrom entries after the two required slots,
// each marked optional so a Secret that does not exist yet cannot keep the
// pod from starting. The required slots must stay required.
func TestDeploymentEnvFromOptionalSecrets(t *testing.T) {
	d, _ := renderDeployment(t,
		"--set", "envFromSecret=mctl-api-secrets",
		"--set", "envFromExtraSecret=mctl-api-events",
		"--set", "envFromOptionalSecrets={mctl-api-zitadel-hook,mctl-api-other}",
	)
	got := mainContainer(t, d).EnvFrom
	want := []secretEnvSource{
		{Name: "mctl-api-secrets"},
		{Name: "mctl-api-events"},
		{Name: "mctl-api-zitadel-hook", Optional: true},
		{Name: "mctl-api-other", Optional: true},
	}
	if len(got) != len(want) {
		t.Fatalf("envFrom has %d entries, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i].SecretRef == nil || *got[i].SecretRef != w {
			t.Errorf("envFrom[%d] = %+v, want secretRef %+v", i, got[i].SecretRef, w)
		}
	}
}

func TestDeploymentDefaultRenderHasNoOptionalEnvFrom(t *testing.T) {
	d, _ := renderDeployment(t,
		"--set", "envFromSecret=mctl-api-secrets",
		"--set", "envFromExtraSecret=mctl-api-events",
	)
	for _, e := range mainContainer(t, d).EnvFrom {
		if e.SecretRef == nil || e.SecretRef.Optional {
			t.Errorf("default render has an unexpected envFrom entry: %+v", e.SecretRef)
		}
	}
	if n := len(mainContainer(t, d).EnvFrom); n != 2 {
		t.Errorf("default render has %d envFrom entries, want 2", n)
	}
}

func TestDeploymentSupportIncidentProducerToken(t *testing.T) {
	d, _ := renderDeployment(t)
	if _, ok := findEnv(mainContainer(t, d), "MCTL_SUPPORT_INCIDENT_PRODUCER_TOKEN"); ok {
		t.Error("default render should not set MCTL_SUPPORT_INCIDENT_PRODUCER_TOKEN")
	}

	d, _ = renderDeployment(t, "--set", "supportIncidentProducerTokenSecret=mctl-api-support-incident-producer")
	env, ok := findEnv(mainContainer(t, d), "MCTL_SUPPORT_INCIDENT_PRODUCER_TOKEN")
	if !ok {
		t.Fatal("expected MCTL_SUPPORT_INCIDENT_PRODUCER_TOKEN env to be rendered")
	}
	if env.ValueFrom == nil || env.ValueFrom.SecretKeyRef == nil {
		t.Fatal("expected a secretKeyRef")
	}
	ref := env.ValueFrom.SecretKeyRef
	if ref.Name != "mctl-api-support-incident-producer" || ref.Key != "MCTL_SUPPORT_INCIDENT_PRODUCER_TOKEN" || !ref.Optional {
		t.Errorf("unexpected secretKeyRef: %+v", ref)
	}
}

type ingressPath struct {
	Path string `yaml:"path"`
}

type ingressRule struct {
	Host string `yaml:"host"`
	HTTP struct {
		Paths []ingressPath `yaml:"paths"`
	} `yaml:"http"`
}

type ingress struct {
	Spec struct {
		Rules []ingressRule `yaml:"rules"`
		TLS   []struct {
			Hosts []string `yaml:"hosts"`
		} `yaml:"tls"`
	} `yaml:"spec"`
}

// glovoHostValues is the host entry the canary adds (mctlhq/mctl-api#1006).
var glovoHostValues = []string{
	"--set", "ingress.hosts[0].host=api.mctl.ai",
	"--set", "ingress.hosts[1].host=glovo.mctl.ai",
	"--set", "ingress.hosts[1].paths[0]=/mcp",
	"--set", "ingress.hosts[1].paths[1]=/.well-known/oauth-protected-resource",
}

func renderIngress(t *testing.T, setArgs ...string) (ingress, []byte) {
	t.Helper()
	helmPath := requireHelm(t)
	args := append([]string{"template", "mctl-api", ".", "--show-only", "templates/ingress.yaml"}, setArgs...)
	// #nosec G204 -- see renderDeployment.
	cmd := exec.Command(helmPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("helm template failed: %v\nstderr: %s", err, stderr.String())
	}
	var in ingress
	if err := yaml.Unmarshal(stdout.Bytes(), &in); err != nil {
		t.Fatalf("failed to unmarshal rendered ingress: %v\noutput:\n%s", err, stdout.String())
	}
	return in, stdout.Bytes()
}

func rulePaths(r ingressRule) []string {
	var out []string
	for _, p := range r.HTTP.Paths {
		out = append(out, p.Path)
	}
	return out
}

func ruleByHost(t *testing.T, in ingress, host string) ingressRule {
	t.Helper()
	for _, r := range in.Spec.Rules {
		if r.Host == host {
			return r
		}
	}
	t.Fatalf("no ingress rule for host %q", host)
	return ingressRule{}
}

// Positive control: with the shipped values every host routes the ten
// existing paths, and /glovo is NOT among them (extraPaths is empty).
func TestIngressDefaultRenderUnchanged(t *testing.T) {
	in, _ := renderIngress(t)
	want := []string{"/healthz", "/readyz", "/openapi.yaml", "/docs", "/.well-known", "/oauth", "/identity", "/devloop", "/api", "/mcp"}
	if len(in.Spec.Rules) != 2 {
		t.Fatalf("expected the two default hosts, got %d rules", len(in.Spec.Rules))
	}
	for _, r := range in.Spec.Rules {
		if got := strings.Join(rulePaths(r), " "); got != strings.Join(want, " ") {
			t.Errorf("host %s paths = %q, want %q", r.Host, got, strings.Join(want, " "))
		}
	}
}

func TestIngressEmptyExtraPathsRenderUnchanged(t *testing.T) {
	_, defaultOut := renderIngress(t)
	_, emptyOut := renderIngress(t, "--set", "ingress.extraPaths=null")
	if !bytes.Equal(defaultOut, emptyOut) {
		t.Error("empty ingress.extraPaths should render byte-identical output to the default")
	}
}

func TestIngressHostWithoutPathsKeepsGlobalList(t *testing.T) {
	// Only the Glovo host carries its own paths; api.mctl.ai must not change.
	in, _ := renderIngress(t, glovoHostValues...)
	_, defaultOut := renderIngress(t, "--set", "ingress.hosts[0].host=api.mctl.ai")
	var def ingress
	if err := yaml.Unmarshal(defaultOut, &def); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(rulePaths(ruleByHost(t, in, "api.mctl.ai")), " ")
	want := strings.Join(rulePaths(ruleByHost(t, def, "api.mctl.ai")), " ")
	if got != want {
		t.Errorf("api.mctl.ai paths changed when another host got its own paths: %q vs %q", got, want)
	}
}

func TestIngressRendersGlovoHostWithOwnPathsOnly(t *testing.T) {
	in, _ := renderIngress(t, glovoHostValues...)
	g := rulePaths(ruleByHost(t, in, "glovo.mctl.ai"))
	want := []string{"/mcp", "/.well-known/oauth-protected-resource"}
	if strings.Join(g, " ") != strings.Join(want, " ") {
		t.Errorf("glovo.mctl.ai paths = %v, want exactly %v", g, want)
	}
	// None of the main-router paths may leak onto the Glovo host.
	for _, p := range g {
		switch p {
		case "/healthz", "/readyz", "/docs", "/oauth", "/identity", "/devloop", "/api", "/openapi.yaml", "/.well-known", "/glovo":
			t.Errorf("glovo.mctl.ai must not route %s", p)
		}
	}
	tlsHosts := 0
	for _, tl := range in.Spec.TLS {
		for _, h := range tl.Hosts {
			if h == "glovo.mctl.ai" {
				tlsHosts++
			}
		}
	}
	if tlsHosts != 1 {
		t.Errorf("expected one TLS entry for glovo.mctl.ai, got %d", tlsHosts)
	}
}

func TestIngressExtraPathsAppendToHostsWithoutOwnPaths(t *testing.T) {
	args := append([]string{"--set", "ingress.extraPaths[0]=/glovo"}, glovoHostValues...)
	in, _ := renderIngress(t, args...)
	api := rulePaths(ruleByHost(t, in, "api.mctl.ai"))
	if api[len(api)-1] != "/glovo" || len(api) != 11 {
		t.Errorf("api.mctl.ai paths = %v, want the ten defaults plus /glovo", api)
	}
	for _, p := range rulePaths(ruleByHost(t, in, "glovo.mctl.ai")) {
		if p == "/glovo" {
			t.Error("extraPaths must not reach a host that has its own paths")
		}
	}
}

func TestDeploymentDefaultRenderHasNoGlovoBasketUI(t *testing.T) {
	d, _ := renderDeployment(t)
	c := mainContainer(t, d)
	for _, name := range []string{"GLOVO_BASKET_UI_CLIENT_ID", "GLOVO_BASKET_UI_CLIENT_SECRET"} {
		if _, ok := findEnv(c, name); ok {
			t.Errorf("default render should not set %s", name)
		}
	}
}

func TestDeploymentEmptyGlovoBasketUISecretRendersUnchanged(t *testing.T) {
	_, defaultOut := renderDeployment(t)
	_, emptyOut := renderDeployment(t, "--set", "glovoBasketUISecret=")
	if !bytes.Equal(defaultOut, emptyOut) {
		t.Error("empty glovoBasketUISecret should render byte-identical output to the default")
	}
}

func TestDeploymentRendersGlovoBasketUISecretRefs(t *testing.T) {
	d, _ := renderDeployment(t, "--set", "glovoBasketUISecret=mctl-api-oidc-zitadel")
	c := mainContainer(t, d)
	for _, name := range []string{"GLOVO_BASKET_UI_CLIENT_ID", "GLOVO_BASKET_UI_CLIENT_SECRET"} {
		if n := countEnv(c, name); n != 1 {
			t.Fatalf("expected exactly one %s entry, got %d", name, n)
		}
		e, _ := findEnv(c, name)
		if e.Value != "" || e.ValueFrom == nil || e.ValueFrom.SecretKeyRef == nil {
			t.Fatalf("%s must come from a secretKeyRef only: %+v", name, e)
		}
		ref := e.ValueFrom.SecretKeyRef
		if ref.Name != "mctl-api-oidc-zitadel" || ref.Key != name || !ref.Optional {
			t.Errorf("%s secretKeyRef = %+v", name, ref)
		}
	}
}

func TestDeploymentGlovoBasketUISecretConflictsWithEnv(t *testing.T) {
	helmPath := requireHelm(t)
	// #nosec G204 -- see renderDeployment.
	cmd := exec.Command(helmPath, "template", "mctl-api", ".", "--show-only", "templates/deployment.yaml",
		"--set", "glovoBasketUISecret=mctl-api-oidc-zitadel",
		"--set", "env.GLOVO_BASKET_UI_CLIENT_ID=x")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected the render to fail when the id is set both in env and through the slot")
	}
	if !strings.Contains(string(out), "glovoBasketUISecret") {
		t.Errorf("failure should name glovoBasketUISecret, got: %s", out)
	}
}
