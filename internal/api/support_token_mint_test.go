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

package api

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	mctlmcp "github.com/mctlhq/mctl-api/internal/mcp"
)

// T9: one support.token_mint row per mint, naming the caller's principal and
// the tenant, with the jti and never any part of the minted or the caller's
// token.
func TestAuditSupportTokenMint(t *testing.T) {
	const pid = "prn_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	o := auth.NewOAuthServer("https://api.example", "gh-client", "gh-secret", []byte("test-secret"),
		[]string{testClientRedirect}, auth.NewGitHubValidator(nil))
	o.SupportResource = testSupportResource
	o.PrincipalMode = true
	apiTok, err := o.IssueJWT("alice", pid, nil)
	if err != nil {
		t.Fatal(err)
	}
	caller, err := o.ValidateJWT(apiTok)
	if err != nil {
		t.Fatal(err)
	}
	st, err := o.IssueSupportToken(caller, 11*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	log := audit.NewLogger()
	h := &Handlers{opts: Options{AuditLog: log}}
	rec := mctlmcp.SupportTokenMintRecord{Tool: "mctl_ask_support", Tenant: "karabu", JTI: st.JTI, Audience: st.Audience, ExpiresAt: st.ExpiresAt}

	h.AuditSupportTokenMint(context.Background(), rec)
	if n := len(log.List(10)); n != 0 {
		t.Fatalf("%d rows written with no caller", n)
	}

	h.AuditSupportTokenMint(auth.WithToken(auth.WithUser(context.Background(), caller), apiTok), rec)
	rows := log.List(10)
	if len(rows) != 1 {
		t.Fatalf("rows = %d", len(rows))
	}
	e := rows[0]
	if e.Operation != "support.token_mint" ||
		e.UserID != "alice" || e.PrincipalID != pid || e.Tenant != "karabu" {
		t.Fatalf("entry = %+v", e)
	}
	want := map[string]string{"tool": "mctl_ask_support", "jti": st.JTI, "aud": testSupportResource,
		"exp": st.ExpiresAt.UTC().Format(time.RFC3339), "layer": "mcp"}
	if !maps.Equal(e.Parameters, want) {
		t.Fatalf("parameters = %v, want %v", e.Parameters, want)
	}
	dump := fmt.Sprintf("%#v", e)
	for _, tok := range []string{st.Token, apiTok} {
		for _, seg := range slices.Collect(strings.SplitSeq(tok, "."))[1:] {
			if strings.Contains(dump, seg[:16]) {
				t.Fatalf("audit row carries a token segment")
			}
		}
	}
}
