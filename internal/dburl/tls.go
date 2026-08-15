// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package dburl hardens PostgreSQL connection strings for in-cluster CNPG.
package dburl

import (
	"fmt"
	"net/url"
	"os"
	"strings"
)

// DefaultCNPGCAPath is where the Helm chart mounts the shared-pg CA when
// postgresCA.secretName is set. Used only if the file exists.
const DefaultCNPGCAPath = "/etc/cnpg/ca.crt"

// EnforceTLS upgrades a libpq/pgx connection string so the client requires
// TLS. sslmode=disable/allow/prefer (or a missing sslmode) becomes require,
// or verify-full when a CA file is available. Existing require/verify-*
// modes are left alone. Tests and local Postgres set ALLOW_INSECURE_DB=1.
func EnforceTLS(connStr string) (string, error) {
	if connStr == "" || allowInsecureDB() {
		return connStr, nil
	}
	if strings.Contains(connStr, "://") {
		return enforceURL(connStr)
	}
	return enforceKeyValue(connStr)
}

func allowInsecureDB() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("ALLOW_INSECURE_DB"))) {
	case "1", "true", "yes":
		return true
	default:
		return false
	}
}

func caPath(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if v := strings.TrimSpace(os.Getenv("PGSSLROOTCERT")); v != "" {
		return v
	}
	if fileExists(DefaultCNPGCAPath) {
		return DefaultCNPGCAPath
	}
	return ""
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

func enforceURL(connStr string) (string, error) {
	u, err := url.Parse(connStr)
	if err != nil {
		return "", fmt.Errorf("dburl: parse: %w", err)
	}
	q := u.Query()
	applySSLMode(q)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func applySSLMode(q url.Values) {
	mode := strings.ToLower(q.Get("sslmode"))
	root := caPath(q.Get("sslrootcert"))
	switch mode {
	case "require", "verify-ca", "verify-full":
		if (mode == "verify-ca" || mode == "verify-full") && root != "" && q.Get("sslrootcert") == "" {
			q.Set("sslrootcert", root)
		}
	default:
		if root != "" {
			q.Set("sslmode", "verify-full")
			q.Set("sslrootcert", root)
		} else {
			q.Set("sslmode", "require")
		}
	}
}

func enforceKeyValue(connStr string) (string, error) {
	// Whitespace split is enough for CNPG-generated DSNs (no quoted
	// passwords). Quoted libpq values are not parsed here; EnforceTLS
	// callers must not fall back to the original string on error.
	parts := strings.Fields(connStr)
	vals := make(map[string]string, len(parts))
	order := make([]string, 0, len(parts))
	for _, p := range parts {
		k, v, ok := strings.Cut(p, "=")
		if !ok {
			return "", fmt.Errorf("dburl: invalid key=value pair %q", p)
		}
		if _, exists := vals[k]; !exists {
			order = append(order, k)
		}
		vals[k] = v
	}
	q := url.Values{}
	if m, ok := vals["sslmode"]; ok {
		q.Set("sslmode", m)
	}
	if c, ok := vals["sslrootcert"]; ok {
		q.Set("sslrootcert", c)
	}
	applySSLMode(q)
	if mode := q.Get("sslmode"); mode != "" {
		if _, ok := vals["sslmode"]; !ok {
			order = append(order, "sslmode")
		}
		vals["sslmode"] = mode
	}
	if cert := q.Get("sslrootcert"); cert != "" {
		if _, ok := vals["sslrootcert"]; !ok {
			order = append(order, "sslrootcert")
		}
		vals["sslrootcert"] = cert
	}
	out := make([]string, 0, len(order))
	for _, k := range order {
		out = append(out, k+"="+vals[k])
	}
	return strings.Join(out, " "), nil
}
