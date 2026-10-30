package deployplan

import "fmt"

const redactedPrefix = "redacted:sha256:"

func redactedPath(path string) string { return redactedPrefix + SHA256Hex(path) }

// vaultPathKeys are the base-service chart keys whose value is a Vault path:
// externalSecret.data[].remoteKey, extraExternalSecrets.*.data[].remoteKey,
// dbSecret.vaultPath, registryCredentials.vaultKey and
// workContext.tokenVaultKey. They are matched by name at any depth, so a path
// under a key the chart adds later in the same shape is not shown either.
var vaultPathKeys = map[string]bool{
	"remoteKey":     true,
	"vaultPath":     true,
	"vaultKey":      true,
	"tokenVaultKey": true,
}

// Redact returns a deep copy of values in which every Vault path is replaced
// by redacted:sha256:<hex of the real path>. The hash keeps the digest bound
// to the real path without disclosing it. Kubernetes secret names are not
// credentials and are kept.
func Redact(values map[string]any) map[string]any {
	out := deepCopy(values).(map[string]any)
	redactTree(out)
	return out
}

func redactTree(v any) {
	switch t := v.(type) {
	case map[string]any:
		for k, e := range t {
			if vaultPathKeys[k] {
				if _, nested := e.(map[string]any); !nested && e != nil && fmt.Sprint(e) != "" {
					if _, list := e.([]any); !list {
						t[k] = redactedPath(fmt.Sprint(e))
						continue
					}
				}
			}
			redactTree(e)
		}
	case []any:
		for _, e := range t {
			redactTree(e)
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
