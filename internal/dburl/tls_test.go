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

package dburl

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnforceTLS_Empty(t *testing.T) {
	got, err := EnforceTLS("")
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestEnforceTLS_AllowInsecure(t *testing.T) {
	t.Setenv("ALLOW_INSECURE_DB", "1")
	in := "postgresql://u@db:5432/mctl-api?sslmode=disable"
	got, err := EnforceTLS(in)
	if err != nil {
		t.Fatal(err)
	}
	if got != in {
		t.Fatalf("expected unchanged, got %q", got)
	}
}

func TestEnforceTLS_DisableBecomesRequire(t *testing.T) {
	t.Setenv("ALLOW_INSECURE_DB", "")
	t.Setenv("PGSSLROOTCERT", "")
	in := "postgresql://u@shared-pg-rw.platform-db.svc:5432/mctl-api?sslmode=disable"
	got, err := EnforceTLS(in)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("sslmode") != "require" {
		t.Fatalf("sslmode=%q, want require", u.Query().Get("sslmode"))
	}
	if u.User.Username() != "u" {
		t.Fatalf("user rewritten: %q", u.User.Username())
	}
	if u.Host != "shared-pg-rw.platform-db.svc:5432" {
		t.Fatalf("host rewritten: %q", u.Host)
	}
}

func TestEnforceTLS_MissingModeBecomesRequire(t *testing.T) {
	t.Setenv("ALLOW_INSECURE_DB", "")
	t.Setenv("PGSSLROOTCERT", "")
	got, err := EnforceTLS("postgresql://u@db:5432/mctl-api")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("sslmode") != "require" {
		t.Fatalf("sslmode=%q, want require", u.Query().Get("sslmode"))
	}
}

func TestEnforceTLS_LeavesRequireAndVerify(t *testing.T) {
	t.Setenv("ALLOW_INSECURE_DB", "")
	t.Setenv("PGSSLROOTCERT", "")
	for _, mode := range []string{"require", "verify-ca", "verify-full"} {
		in := "postgresql://u@db:5432/mctl-api?sslmode=" + mode
		got, err := EnforceTLS(in)
		if err != nil {
			t.Fatal(err)
		}
		u, err := url.Parse(got)
		if err != nil {
			t.Fatal(err)
		}
		if u.Query().Get("sslmode") != mode {
			t.Fatalf("sslmode=%q, want %s", u.Query().Get("sslmode"), mode)
		}
	}
}

func TestEnforceTLS_VerifyFullWhenCAPresent(t *testing.T) {
	t.Setenv("ALLOW_INSECURE_DB", "")
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(ca, []byte("dummy"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PGSSLROOTCERT", ca)
	got, err := EnforceTLS("postgresql://u@db:5432/mctl-api?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("sslmode") != "verify-full" {
		t.Fatalf("sslmode=%q, want verify-full", u.Query().Get("sslmode"))
	}
	if u.Query().Get("sslrootcert") != ca {
		t.Fatalf("sslrootcert=%q, want %q", u.Query().Get("sslrootcert"), ca)
	}
}

func TestEnforceTLS_KeyValue(t *testing.T) {
	t.Setenv("ALLOW_INSECURE_DB", "")
	t.Setenv("PGSSLROOTCERT", "")
	got, err := EnforceTLS("host=db user=u dbname=mctl-api sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "sslmode=require") {
		t.Fatalf("got %q, want sslmode=require", got)
	}
	if !strings.Contains(got, "host=db") || !strings.Contains(got, "user=u") {
		t.Fatalf("lost fields: %q", got)
	}
}
