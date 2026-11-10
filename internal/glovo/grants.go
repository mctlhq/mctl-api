// Copyright 2026 MCTL Authors
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

package glovo

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// GrantRow is one row of the runtime role's grant table (mctl-api#957 design
// section 6d.1) for a table in schema glovo. Privileges are table-level;
// UpdateColumns is a column-level UPDATE grant and is exclusive with a
// table-level UPDATE.
type GrantRow struct {
	Table         string
	Privileges    []string
	UpdateColumns []string
	Description   string
}

var (
	grantsMu       sync.Mutex
	expectedGrants = map[string]GrantRow{}
)

var knownPrivileges = map[string]bool{"SELECT": true, "INSERT": true, "UPDATE": true, "DELETE": true}

// RegisterGrants registers the rows of the calling slice. Each slice calls it
// from its own package init for its own tables. A duplicate table, an unknown
// privilege or a missing description panics at init time.
func RegisterGrants(rows ...GrantRow) {
	grantsMu.Lock()
	defer grantsMu.Unlock()
	for _, r := range rows {
		if r.Table == "" || r.Description == "" {
			panic("glovo: grant row needs a table and a description")
		}
		if _, dup := expectedGrants[r.Table]; dup {
			panic("glovo: duplicate grant row for " + r.Table)
		}
		for _, p := range r.Privileges {
			if !knownPrivileges[p] {
				panic("glovo: unknown privilege " + p)
			}
			if p == "UPDATE" && len(r.UpdateColumns) > 0 {
				panic("glovo: table-level UPDATE and column UPDATE are exclusive for " + r.Table)
			}
		}
		r.Privileges = append([]string(nil), r.Privileges...)
		sort.Strings(r.Privileges)
		r.UpdateColumns = append([]string(nil), r.UpdateColumns...)
		sort.Strings(r.UpdateColumns)
		expectedGrants[r.Table] = r
	}
}

func grantFor(table string) (GrantRow, bool) {
	grantsMu.Lock()
	defer grantsMu.Unlock()
	r, ok := expectedGrants[table]
	return r, ok
}

// GrantFor returns the registered row of a table in schema glovo.
func GrantFor(table string) (GrantRow, bool) { return grantFor(table) }

// grantsSnapshot renders the registry as the text of testdata/grants.golden.
func grantsSnapshot() string {
	grantsMu.Lock()
	defer grantsMu.Unlock()
	names := make([]string, 0, len(expectedGrants))
	for n := range expectedGrants {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		r := expectedGrants[n]
		fmt.Fprintf(&b, "glovo.%s: %s", n, strings.Join(r.Privileges, ","))
		if len(r.UpdateColumns) > 0 {
			fmt.Fprintf(&b, " UPDATE(%s)", strings.Join(r.UpdateColumns, ","))
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// The #959 rows of mctl-api#957 design section 6d.1, plus the schema version
// table the runtime role reads at start.
func init() {
	RegisterGrants(
		GrantRow{Table: "glovo_installs", Privileges: []string{"SELECT", "INSERT", "UPDATE"}, Description: "install rows"},
		GrantRow{Table: "glovo_connections", Privileges: []string{"SELECT", "INSERT", "UPDATE"}, Description: "connection rows, never deleted"},
		GrantRow{Table: "glovo_connect_requests", Privileges: []string{"SELECT", "INSERT", "UPDATE", "DELETE"}, Description: "idempotency rows, 24 h cleanup by the handoff slice"},
		GrantRow{Table: "glovo_audit_events", Privileges: []string{"SELECT", "INSERT"}, Description: "append-only audit events"},
		GrantRow{Table: "glovo_pilot_allowlist", Privileges: []string{"SELECT", "INSERT", "DELETE"}, Description: "pilot allowlist, written by the allowlist slice"},
		GrantRow{Table: "glovo_schema_version", Privileges: []string{"SELECT"}, Description: "recorded schema version, read at start"},
	)
}
