package deployplan

import "fmt"

const redactedPrefix = "redacted:sha256:"

func redactedPath(path string) string { return redactedPrefix + SHA256Hex(path) }

// Redact returns a deep copy of values in which every Vault path is replaced
// by redacted:sha256:<hex of the real path>: externalSecret.data[].remoteKey,
// extraExternalSecrets.*.data[].remoteKey and dbSecret.vaultPath. The hash
// keeps the digest bound to the real path without disclosing it. Kubernetes
// secret names are not credentials and are kept.
func Redact(values map[string]any) map[string]any {
	out := deepCopy(values).(map[string]any)
	if ext, ok := out["externalSecret"].(map[string]any); ok {
		redactData(ext["data"])
	}
	if extras, ok := out["extraExternalSecrets"].(map[string]any); ok {
		for _, v := range extras {
			if es, ok := v.(map[string]any); ok {
				redactData(es["data"])
			}
		}
	}
	if db, ok := out["dbSecret"].(map[string]any); ok {
		if p, present := db["vaultPath"]; present && p != nil && fmt.Sprint(p) != "" {
			db["vaultPath"] = redactedPath(fmt.Sprint(p))
		}
	}
	return out
}

func redactData(data any) {
	list, ok := data.([]any)
	if !ok {
		return
	}
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if k, present := m["remoteKey"]; present && k != nil && fmt.Sprint(k) != "" {
			m["remoteKey"] = redactedPath(fmt.Sprint(k))
		}
	}
}

func deepCopy(v any) any {
	switch t := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, e := range t {
			m[k] = deepCopy(e)
		}
		return m
	case []any:
		l := make([]any, len(t))
		for i, e := range t {
			l[i] = deepCopy(e)
		}
		return l
	default:
		return v
	}
}
