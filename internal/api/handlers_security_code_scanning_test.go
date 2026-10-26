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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/securityfindings"
)

const (
	csSecret    = "code-scanning-secret-0123456789abcdef"
	csOrgSecret = "org-webhook-secret-0123456789abcdef!"
	csSHA       = "0123456789abcdef0123456789abcdef01234567"
)

type fakeIngester struct {
	calls   int
	pc      securityfindings.ProviderContext
	batch   securityfindings.Batch
	results []securityfindings.ItemResult
	err     error
	block   bool
}

func (f *fakeIngester) IngestBatch(ctx context.Context, pc securityfindings.ProviderContext, b securityfindings.Batch) ([]securityfindings.ItemResult, error) {
	f.calls++
	f.pc, f.batch = pc, b
	if f.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return f.results, f.err
}

func csProviders() map[string]auth.SecurityProviderConfig {
	return map[string]auth.SecurityProviderConfig{
		CodeScanningProviderRef: {Ref: CodeScanningProviderRef, MaxStrength: "provider_claim", Tenants: []string{"admins"}},
	}
}

func csConfig(t *testing.T) *CodeScanningConfig {
	t.Helper()
	cfg, err := ParseCodeScanningConfig(`{"repositories":{"MctlHQ/mctl-api":"admins"},"tools":["Trivy"],"actions":["created","appeared_in_branch","reopened","reopened_by_user","fixed","closed_by_user"]}`, csProviders())
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func csHandlers(t *testing.T, ing SecurityIngester) *Handlers {
	return &Handlers{opts: Options{
		GitHubWebhookSecret: csOrgSecret, CodeScanningWebhookSecret: csSecret,
		CodeScanningConfig: csConfig(t), CodeScanningIngester: ing, SecurityProviders: csProviders(),
	}}
}

func csSign(secret string, body string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(body))
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

// csBody follows the GitHub code_scanning_alert webhook payload: top-level
// action, ref, commit_oid, alert{number, rule, tool, most_recent_instance}
// and repository.
func csBody(action, ref, commit string, number int, extra string) string {
	commitJSON := "null"
	if commit != "" {
		commitJSON = `"` + commit + `"`
	}
	return fmt.Sprintf(`{"action":%q,"ref":%q,"commit_oid":%s,%s
"alert":{"number":%d,"html_url":"https://github.com/mctlhq/mctl-api/security/code-scanning/%d",
"rule":{"id":"CVE-2026-1","severity":"error","security_severity_level":"high","description":"bad dep"},
"tool":{"name":"Trivy","version":"0.60"},
"most_recent_instance":{"ref":%q,"commit_sha":%q,"location":{"path":"go.mod","start_line":3,"end_line":4},"message":{"text":"msg"}}},
"repository":{"full_name":"mctlhq/mctl-api"}}`, action, ref, commitJSON, extra, number, number, ref, csSHA)
}

func csPost(h *Handlers, event, body, sig string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/security/webhooks/github-code-scanning", strings.NewReader(body))
	req.Header.Set("X-GitHub-Event", event)
	req.Header.Set("X-GitHub-Delivery", "guid-1")
	if sig != "" {
		req.Header.Set("X-Hub-Signature-256", sig)
	}
	rr := httptest.NewRecorder()
	h.HandleGitHubCodeScanningWebhook(rr, req)
	return rr
}

func csCount(result string) float64 {
	return testutil.ToFloat64(securityWebhookDeliveries.WithLabelValues(CodeScanningProviderRef, result))
}

func created() []securityfindings.ItemResult {
	return []securityfindings.ItemResult{{Status: securityfindings.ItemCreated}}
}

func TestCodeScanningValidDelivery(t *testing.T) {
	ing := &fakeIngester{results: created()}
	h := csHandlers(t, ing)
	before := csCount(csResultAccepted)
	body := csBody("created", "refs/heads/main", csSHA, 7,
		`"provider":"evil","principal_id":"admin","tenant":"other",`)
	rr := csPost(h, "code_scanning_alert", body, csSign(csSecret, body))
	if rr.Code != http.StatusAccepted || !strings.Contains(rr.Body.String(), `"accepted"`) {
		t.Fatalf("got %d %s", rr.Code, rr.Body)
	}
	if csCount(csResultAccepted) != before+1 {
		t.Error("accepted counter not incremented")
	}
	pc := ing.pc
	if pc.Ref != "github-code-scanning" || pc.PrincipalID != "service:security-provider:github-code-scanning" ||
		pc.MaxStrength != securityfindings.StrengthProviderClaim || len(pc.Tenants) != 1 || pc.Tenants[0] != "admins" || pc.AnyTenant {
		t.Errorf("provider context = %+v", pc)
	}
	if len(ing.batch.Observations) != 1 || ing.batch.DeliveryID != "guid-1" {
		t.Fatalf("batch = %+v", ing.batch)
	}
	o := ing.batch.Observations[0]
	if o.Tenant != "admins" || o.Identity != "CVE-2026-1" || o.SourceFindingID != "github:mctlhq/mctl-api/code-scanning/7" ||
		o.ClaimedAction != securityfindings.ClaimPresent || o.ObservedRevision != csSHA ||
		o.Subject.Repository != "mctlhq/mctl-api" || o.Subject.Path != "go.mod" || o.Subject.Location != "3:4" || o.Subject.RuleID != "CVE-2026-1" {
		t.Errorf("observation = %+v", o)
	}
	if strings.Contains(o.Untrusted.ClaimedProvider, "evil") {
		t.Errorf("payload provider leaked: %+v", o.Untrusted)
	}
}

func TestCodeScanningActionMappingAndStableIdentity(t *testing.T) {
	cases := []struct {
		action, claim, ref, commit, wantRev string
	}{
		{"created", securityfindings.ClaimPresent, "refs/heads/main", csSHA, csSHA},
		{"appeared_in_branch", securityfindings.ClaimPresent, "refs/heads/feat", csSHA, csSHA},
		{"reopened", securityfindings.ClaimPresent, "refs/heads/main", csSHA, csSHA},
		{"reopened_by_user", securityfindings.ClaimPresent, "", "", ""},
		{"fixed", securityfindings.ClaimFixed, "refs/heads/dev", csSHA, csSHA},
		{"closed_by_user", securityfindings.ClaimWithdrawn, "", "", ""},
	}
	for _, c := range cases {
		ing := &fakeIngester{results: created()}
		h := csHandlers(t, ing)
		body := csBody(c.action, c.ref, c.commit, 42, "")
		rr := csPost(h, "code_scanning_alert", body, csSign(csSecret, body))
		if rr.Code != http.StatusAccepted {
			t.Fatalf("%s: %d %s", c.action, rr.Code, rr.Body)
		}
		o := ing.batch.Observations[0]
		if o.ClaimedAction != c.claim || o.ObservedRevision != c.wantRev {
			t.Errorf("%s: action=%s rev=%q", c.action, o.ClaimedAction, o.ObservedRevision)
		}
		if o.SourceFindingID != "github:mctlhq/mctl-api/code-scanning/42" {
			t.Errorf("%s: source id %q depends on ref/action", c.action, o.SourceFindingID)
		}
	}
}

func TestCodeScanningSignatureRejected(t *testing.T) {
	body := csBody("created", "refs/heads/main", csSHA, 1, "")
	for name, sig := range map[string]string{
		"absent": "", "malformed": "sha256=zz", "org secret": csSign(csOrgSecret, body), "wrong prefix": "sha1=ab",
	} {
		ing := &fakeIngester{results: created()}
		before := csCount(csResultSignatureInvalid)
		rr := csPost(csHandlers(t, ing), "code_scanning_alert", body, sig)
		if rr.Code != http.StatusUnauthorized || ing.calls != 0 || csCount(csResultSignatureInvalid) != before+1 {
			t.Errorf("%s: code=%d calls=%d", name, rr.Code, ing.calls)
		}
	}
}

func TestCodeScanningIgnored(t *testing.T) {
	good := csBody("created", "refs/heads/main", csSHA, 1, "")
	other := strings.Replace(good, `"full_name":"mctlhq/mctl-api"`, `"full_name":"other/repo"`, 1)
	tool := strings.Replace(good, `"name":"Trivy"`, `"name":"CodeQL"`, 1)
	cases := map[string][2]string{
		"ping":       {"ping", good},
		"push event": {"push", good},
		"action":     {"code_scanning_alert", csBody("dismissed", "r", csSHA, 1, "")},
		"repository": {"code_scanning_alert", other},
		"tool":       {"code_scanning_alert", tool},
	}
	for name, c := range cases {
		ing := &fakeIngester{results: created()}
		before := csCount(csResultIgnored)
		rr := csPost(csHandlers(t, ing), c[0], c[1], csSign(csSecret, c[1]))
		if rr.Code != http.StatusAccepted || !strings.Contains(rr.Body.String(), `"ignored"`) || ing.calls != 0 || csCount(csResultIgnored) != before+1 {
			t.Errorf("%s: %d %s calls=%d", name, rr.Code, rr.Body, ing.calls)
		}
	}
}

func TestCodeScanningStoreOutcomes(t *testing.T) {
	body := csBody("created", "refs/heads/main", csSHA, 1, "")
	cases := []struct {
		name string
		ing  SecurityIngester
		code int
		want string
	}{
		{"duplicate", &fakeIngester{results: []securityfindings.ItemResult{{Status: securityfindings.ItemDuplicate}}}, 202, "duplicate"},
		{"nil store", nil, 503, "store_unavailable"},
		{"error", &fakeIngester{err: errors.New("db down")}, 503, "store_unavailable"},
		{"internal", &fakeIngester{results: []securityfindings.ItemResult{{Status: securityfindings.ItemRejected, Code: securityfindings.CodeInternal}}}, 503, "store_unavailable"},
		{"rejected", &fakeIngester{results: []securityfindings.ItemResult{{Status: securityfindings.ItemRejected, Code: securityfindings.CodeTenantDenied}}}, 422, "rejected"},
		{"no results", &fakeIngester{}, 503, "store_unavailable"},
	}
	for _, c := range cases {
		h := csHandlers(t, c.ing)
		if c.ing == nil {
			h.opts.CodeScanningIngester = nil
		}
		rr := csPost(h, "code_scanning_alert", body, csSign(csSecret, body))
		if rr.Code != c.code || !strings.Contains(rr.Body.String(), `"`+c.want+`"`) {
			t.Errorf("%s: %d %s", c.name, rr.Code, rr.Body)
		}
	}
}

func TestCodeScanningMalformedAndOversized(t *testing.T) {
	for name, mut := range map[string]func(string) string{
		"rule id": func(s string) string { return strings.Replace(s, `"id":"CVE-2026-1"`, `"id":""`, 1) },
		"number":  func(s string) string { return strings.Replace(s, `"number":1,`, `"number":0,`, 1) },
		"path":    func(s string) string { return strings.Replace(s, `"path":"go.mod"`, `"path":""`, 1) },
	} {
		ing := &fakeIngester{results: created()}
		body := mut(csBody("created", "r", csSHA, 1, ""))
		rr := csPost(csHandlers(t, ing), "code_scanning_alert", body, csSign(csSecret, body))
		if rr.Code != http.StatusBadRequest || ing.calls != 0 {
			t.Errorf("%s: %d calls=%d", name, rr.Code, ing.calls)
		}
	}
	big := strings.Repeat("a", maxGitHubWebhookBytes+1)
	rr := csPost(csHandlers(t, &fakeIngester{}), "code_scanning_alert", big, csSign(csSecret, big))
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized: %d", rr.Code)
	}
	bad := "{not json"
	rr = csPost(csHandlers(t, &fakeIngester{}), "code_scanning_alert", bad, csSign(csSecret, bad))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("bad json: %d", rr.Code)
	}
}

func TestCodeScanningDisabledConfig(t *testing.T) {
	body := csBody("created", "r", csSHA, 1, "")
	mk := func(mod func(*Options)) *Handlers {
		h := csHandlers(t, &fakeIngester{results: created()})
		mod(&h.opts)
		return h
	}
	for name, h := range map[string]*Handlers{
		"no secret":    mk(func(o *Options) { o.CodeScanningWebhookSecret = "" }),
		"short secret": mk(func(o *Options) { o.CodeScanningWebhookSecret = "short" }),
		"same secret":  mk(func(o *Options) { o.GitHubWebhookSecret = csSecret }),
		"no config":    mk(func(o *Options) { o.CodeScanningConfig = nil }),
		"no provider":  mk(func(o *Options) { o.SecurityProviders = nil }),
	} {
		rr := csPost(h, "code_scanning_alert", body, csSign(csSecret, body))
		if rr.Code != http.StatusServiceUnavailable {
			t.Errorf("%s: %d", name, rr.Code)
		}
	}
}

func TestParseCodeScanningConfig(t *testing.T) {
	good := `{"repositories":{"a/b":"admins"},"tools":["trivy"],"actions":["created"]}`
	if _, err := ParseCodeScanningConfig(good, csProviders()); err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]string{
		"json":       `{`,
		"foreign":    `{"provider_ref":"trivy","repositories":{"a/b":"admins"},"tools":["t"],"actions":["created"]}`,
		"action":     `{"repositories":{"a/b":"admins"},"tools":["t"],"actions":["dismissed"]}`,
		"no repos":   `{"repositories":{},"tools":["t"],"actions":["created"]}`,
		"no tools":   `{"repositories":{"a/b":"admins"},"tools":[],"actions":["created"]}`,
		"empty ten":  `{"repositories":{"a/b":""},"tools":["t"],"actions":["created"]}`,
		"tenant out": `{"repositories":{"a/b":"nope"},"tools":["t"],"actions":["created"]}`,
	} {
		if _, err := ParseCodeScanningConfig(raw, csProviders()); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, err := ParseCodeScanningConfig(good, nil); err == nil {
		t.Error("missing provider entry must fail")
	}
}

func TestCodeScanningMetricsPreinitialized(t *testing.T) {
	for _, r := range []string{csResultAccepted, csResultDuplicate, csResultIgnored, csResultSignatureInvalid, csResultStoreUnavailable, csResultRejected} {
		if n := testutil.CollectAndCount(securityWebhookDeliveries); n < 6 {
			t.Fatalf("series = %d", n)
		}
		_ = csCount(r)
	}
}
