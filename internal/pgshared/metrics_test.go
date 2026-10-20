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

package pgshared

import (
	"context"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

const secretConn = "postgres://u:hunter2@127.0.0.1:1/db?sslmode=disable&pool_max_conns=3" //nolint:gosec // G101: a fake password the test asserts never reaches a label

func gather(t *testing.T) string {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(collector{})
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	var b strings.Builder
	for _, mf := range mfs {
		b.WriteString(mf.String())
		b.WriteByte('\n')
	}
	return b.String()
}

func TestCollectorReportsSharedPools(t *testing.T) {
	withSharing(t)
	ctx := context.Background()
	a, err := Open(ctx, secretConn)
	if err != nil {
		t.Fatal(err)
	}
	defer Release(a)
	// Same database through a different string: a second pool, but the same
	// label set, which must be summed rather than emitted twice.
	b, err := Open(ctx, secretConn+"&application_name=x")
	if err != nil {
		t.Fatal(err)
	}
	defer Release(b)

	// Checked before the series count: the registry key is the connection
	// string, and a label taken from it would carry the password.
	out := gather(t)
	for _, leak := range []string{"hunter2", "postgres://", "application_name"} {
		if strings.Contains(out, leak) {
			t.Fatalf("metrics expose %q:\n%s", leak, out)
		}
	}

	if n := testutil.CollectAndCount(collector{}, "mctl_api_db_pool_max_conns"); n != 1 {
		t.Fatalf("max_conns series = %d, want 1 (one database)", n)
	}
	want := `
# HELP mctl_api_db_pool_max_conns Configured maximum connections of the shared pools for this database.
# TYPE mctl_api_db_pool_max_conns gauge
mctl_api_db_pool_max_conns{database="db",host="127.0.0.1"} 6
`
	if err := testutil.CollectAndCompare(collector{}, strings.NewReader(want), "mctl_api_db_pool_max_conns"); err != nil {
		t.Fatal(err)
	}

	got := Pools()
	if len(got) != 2 || got[0].Database != "db" || got[0].MaxConns != 3 {
		t.Fatalf("Pools() = %+v, want two pools of 3 on db", got)
	}
}

func TestCollectorIsEmptyWithoutSharing(t *testing.T) {
	p, err := Open(context.Background(), secretConn)
	if err != nil {
		t.Fatal(err)
	}
	defer Release(p)
	if n := testutil.CollectAndCount(collector{}); n != 0 {
		t.Fatalf("collected %d series from unshared pools, want 0", n)
	}
	if got := Pools(); len(got) != 0 {
		t.Fatalf("Pools() = %+v, want none", got)
	}
}
