package deployplan

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// previewSetKeys is the set of helm --set keys wft-preview-deploy passes
// after the rewritten values file. TestUpstreamKeysMatchCompiler compares it
// with the snapshot of the workflow template, so a re-vendored template with
// a different set turns the test red.
var previewSetKeys = []string{
	"image.tag",
	"ingress.enabled",
	"ingress.className",
	`ingress.annotations.cert-manager\.io/cluster-issuer`,
	"ingress.hosts",
	"ingress.tls[0].secretName",
	"ingress.tls[0].hosts",
	"blueGreen.enabled",
	"dbInitJob.enabled",
	"service.port",
	`podLabels.mctl\.ai/preview`,
	`podLabels.mctl\.ai/preview-id`,
}

// intentYQPaths are the yq assignment targets of tpl-git-commit that the
// compiler reproduces for intent-derived changes. The remaining intent keys
// (replicaCount, resources, service.port) have no yq assignment in
// tpl-git-commit: service.port is a helm --set of the preview template
// (above), the other two are set by this compiler alone.
var intentYQPaths = []string{
	".probes.liveness.path",
	".probes.readiness.path",
	".env[strenv(KEY)]",
	".externalSecret.targetSecret",
	".externalSecret.data",
	".envFrom",
}

// CompilePreview computes the effective preview Helm values for a service:
// before is what the current base would deploy as a preview with no intent
// changes, after is the same with the intent applied. Both go through the
// preview rewrite of rewrite_preview_values.py and the fixed helm --set
// overrides of wft-preview-deploy. Neither is redacted; callers redact.
func CompilePreview(base []byte, in Intent, previewID, host string) (before, after map[string]any, err error) {
	parsed, err := parseValues(base)
	if err != nil {
		return nil, nil, err
	}
	before, err = effective(parsed, nil, in, previewID, host)
	if err != nil {
		return nil, nil, err
	}
	after, err = effective(parsed, &in, in, previewID, host)
	if err != nil {
		return nil, nil, err
	}
	return before, after, nil
}

func parseValues(base []byte) (map[string]any, error) {
	var doc any
	if err := yaml.Unmarshal(base, &doc); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrValuesUnparseable, err)
	}
	norm, err := normalize(doc)
	if err != nil {
		return nil, err
	}
	m, ok := norm.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: the document is not a mapping", ErrValuesUnparseable)
	}
	return m, nil
}

// normalize makes every mapping a map[string]any, refusing non-string keys.
func normalize(v any) (any, error) {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			n, err := normalize(e)
			if err != nil {
				return nil, err
			}
			out[k] = n
		}
		return out, nil
	case map[any]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			ks, ok := k.(string)
			if !ok {
				return nil, fmt.Errorf("%w: non-string mapping key %v", ErrValuesUnparseable, k)
			}
			n, err := normalize(e)
			if err != nil {
				return nil, err
			}
			out[ks] = n
		}
		return out, nil
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			n, err := normalize(e)
			if err != nil {
				return nil, err
			}
			out[i] = n
		}
		return out, nil
	default:
		return v, nil
	}
}

func effective(base map[string]any, apply *Intent, id Intent, previewID, host string) (map[string]any, error) {
	v := deepCopy(base).(map[string]any)
	if apply != nil {
		applyIntent(v, *apply)
	}
	rewritten, err := rewriteValues(v, id.Metadata.Tenant, id.Metadata.Service)
	if err != nil {
		return nil, err
	}
	if err := assertNoProdTeamPaths(rewritten, id.Metadata.Tenant); err != nil {
		return nil, err
	}
	applyPreviewOverrides(rewritten, id, previewID, host)
	return rewritten, nil
}

// ── intent: the way tpl-git-commit applies deploy parameters ───────────────

func sub(m map[string]any, key string) map[string]any {
	if c, ok := m[key].(map[string]any); ok {
		return c
	}
	c := map[string]any{}
	m[key] = c
	return c
}

func applyIntent(v map[string]any, in Intent) {
	rt := in.Spec.Runtime
	sub(v, "service")["port"] = rt.Port
	sub(sub(v, "probes"), "liveness")["path"] = rt.HealthPath
	sub(sub(v, "probes"), "readiness")["path"] = rt.HealthPath
	v["replicaCount"] = rt.Replicas
	if r := in.Spec.Resources; r != nil {
		v["resources"] = map[string]any{
			"requests": map[string]any{"cpu": r.Requests.CPU, "memory": r.Requests.Memory},
			"limits":   map[string]any{"cpu": r.Limits.CPU, "memory": r.Limits.Memory},
		}
	}
	if len(in.Spec.Env) > 0 {
		env := sub(v, "env")
		for k, val := range in.Spec.Env {
			env[k] = val
		}
	}
	if len(in.Spec.SecretRefs) > 0 {
		secretName := in.Metadata.Service + "-secrets"
		ext := sub(v, "externalSecret")
		ext["targetSecret"] = secretName
		data, ok := ext["data"].([]any)
		if !ok {
			data = []any{}
		}
		for _, ref := range in.Spec.SecretRefs {
			exists := false
			for _, item := range data {
				if m, ok := item.(map[string]any); ok && m["secretKey"] == ref.Env {
					exists = true
					break
				}
			}
			if exists {
				continue // tpl-git-commit adds only a missing secretKey
			}
			data = append(data, map[string]any{
				"secretKey": ref.Env,
				"remoteKey": "teams/" + in.Metadata.Tenant + "/" + in.Metadata.Service,
				"property":  ref.Property,
			})
		}
		ext["data"] = data
		envFrom, _ := v["envFrom"].([]any)
		kept := make([]any, 0, len(envFrom)+1)
		for _, e := range envFrom {
			if m, ok := e.(map[string]any); ok {
				if sr, ok := m["secretRef"].(map[string]any); ok && sr["name"] == secretName {
					continue
				}
			}
			kept = append(kept, e)
		}
		v["envFrom"] = append(kept, map[string]any{"secretRef": map[string]any{"name": secretName}})
	}
}

// ── wft-preview-deploy: the fixed helm --set overrides ─────────────────────

func applyPreviewOverrides(v map[string]any, in Intent, previewID, host string) {
	sub(v, "image")["tag"] = "rev-" + in.Spec.Source.Revision
	ing := sub(v, "ingress")
	ing["enabled"] = true
	ing["className"] = "traefik"
	sub(ing, "annotations")["cert-manager.io/cluster-issuer"] = "letsencrypt-prod"
	ing["hosts"] = []any{host}
	tls, _ := ing["tls"].([]any)
	if len(tls) == 0 {
		tls = []any{map[string]any{}}
	}
	first, ok := tls[0].(map[string]any)
	if !ok {
		first = map[string]any{}
		tls[0] = first
	}
	first["secretName"] = "preview-" + in.Metadata.Service + "-" + previewID + "-tls"
	first["hosts"] = []any{host}
	ing["tls"] = tls
	sub(v, "blueGreen")["enabled"] = false
	sub(v, "dbInitJob")["enabled"] = false
	labels := sub(v, "podLabels")
	labels["mctl.ai/preview"] = "true"
	labels["mctl.ai/preview-id"] = previewID
}

// ── rewrite_preview_values.py ──────────────────────────────────────────────

const dataPrefix = "secret/data/"

func stripDataPrefix(key string) (string, string) {
	if strings.HasPrefix(key, dataPrefix) {
		return dataPrefix, key[len(dataPrefix):]
	}
	return "", key
}

func refuse(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrPreviewValuesRefused}, a...)...)
}

func rewriteRemoteKey(key, team string) (string, error) {
	if key == "" {
		return key, nil
	}
	prefix, path := stripDataPrefix(key)
	if strings.HasPrefix(path, "platform/") {
		return key, nil
	}
	teamsPrefix := "teams/" + team + "/"
	if !strings.HasPrefix(path, "teams/") {
		return "", refuse("a secret path is neither tenant-scoped nor a platform path")
	}
	if !strings.HasPrefix(path, teamsPrefix) {
		return "", refuse("a secret path is outside the tenant's own prefix")
	}
	rest := path[len(teamsPrefix):]
	svc, remainder, _ := strings.Cut(rest, "/")
	if strings.HasPrefix(remainder, "preview/") || remainder == "preview" {
		return key, nil
	}
	n := "teams/" + team + "/" + svc + "/preview"
	if remainder != "" {
		n += "/" + remainder
	}
	return prefix + n, nil
}

func remoteKeysInData(data any) []string {
	list, ok := data.([]any)
	if !ok {
		return nil
	}
	var keys []string
	for _, item := range list {
		if m, ok := item.(map[string]any); ok && truthy(m["remoteKey"]) {
			keys = append(keys, fmt.Sprint(m["remoteKey"]))
		}
	}
	return keys
}

// truthy mirrors Python truthiness for the values a remoteKey can hold.
func truthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case string:
		return t != ""
	case bool:
		return t
	case int:
		return t != 0
	case float64:
		return t != 0
	default:
		return true
	}
}

func classifyKeys(keys []string) string {
	hasPlatform, hasTeam := false, false
	for _, k := range keys {
		_, path := stripDataPrefix(k)
		if strings.HasPrefix(path, "platform/") {
			hasPlatform = true
		} else if strings.HasPrefix(path, "teams/") {
			hasTeam = true
		}
	}
	switch {
	case hasPlatform && hasTeam:
		return "mixed"
	case hasTeam:
		return "team"
	case hasPlatform:
		return "platform"
	}
	return "empty"
}

func forceTenantStore(obj map[string]any) {
	obj["store"] = "tenant-store"
	obj["storeKind"] = "SecretStore"
}

func rewriteDataList(data any, team string) error {
	list, ok := data.([]any)
	if !ok {
		return nil
	}
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if _, has := m["remoteKey"]; has {
			k, err := rewriteRemoteKey(fmt.Sprint(m["remoteKey"]), team)
			if err != nil {
				return err
			}
			m["remoteKey"] = k
		}
	}
	return nil
}

// rewriteValues ports rewrite_values: tenant Vault paths move under preview/
// and team ExternalSecrets are forced onto the namespaced tenant-store.
func rewriteValues(values map[string]any, team, _ string) (map[string]any, error) {
	out := deepCopy(values).(map[string]any)

	if ext, ok := out["externalSecret"].(map[string]any); ok {
		if err := rewriteDataList(ext["data"], team); err != nil {
			return nil, err
		}
		switch classifyKeys(remoteKeysInData(ext["data"])) {
		case "mixed":
			return nil, refuse("externalSecret mixes platform and tenant keys")
		case "team":
			forceTenantStore(ext)
		}
	}
	if extras, ok := out["extraExternalSecrets"].(map[string]any); ok {
		for _, name := range sortedKeys(extras) {
			es, ok := extras[name].(map[string]any)
			if !ok {
				continue
			}
			if err := rewriteDataList(es["data"], team); err != nil {
				return nil, err
			}
			switch classifyKeys(remoteKeysInData(es["data"])) {
			case "mixed":
				return nil, refuse("extraExternalSecrets.%s mixes platform and tenant keys", name)
			case "team":
				forceTenantStore(es)
			}
		}
	}
	if db, ok := out["dbSecret"].(map[string]any); ok && truthy(db["vaultPath"]) {
		p, err := rewriteRemoteKey(fmt.Sprint(db["vaultPath"]), team)
		if err != nil {
			return nil, err
		}
		db["vaultPath"] = p
		if _, path := stripDataPrefix(p); strings.HasPrefix(path, "teams/") {
			forceTenantStore(db)
		}
	}
	return out, nil
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sortStrings(keys)
	return keys
}

// assertNoProdTeamPaths is the script's belt-and-suspenders walk: any
// remaining teams/<team>/ path must be under preview/.
func assertNoProdTeamPaths(values map[string]any, team string) error {
	needle := "teams/" + team + "/"
	var walk func(obj any, loc string) error
	walk = func(obj any, loc string) error {
		switch t := obj.(type) {
		case map[string]any:
			for _, k := range sortedKeys(t) {
				if err := walk(t[k], loc+"."+k); err != nil {
					return err
				}
			}
		case []any:
			for i, e := range t {
				if err := walk(e, fmt.Sprintf("%s[%d]", loc, i)); err != nil {
					return err
				}
			}
		case string:
			_, path := stripDataPrefix(t)
			if strings.HasPrefix(path, needle) && !strings.Contains(path, "/preview/") && !strings.HasSuffix(path, "/preview") {
				return refuse("%s still points at a production secret path", loc)
			}
		}
		return nil
	}
	for _, k := range []string{"externalSecret", "extraExternalSecrets", "dbSecret"} {
		if err := walk(values[k], k); err != nil {
			return err
		}
	}
	return nil
}

func sortStrings(s []string) { sort.Strings(s) }
