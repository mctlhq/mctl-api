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

package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/control"
)

// contractDir holds the artifacts the control worker (#990) tests against.
const contractDir = "../glovo/control/contract"

// contractCase is one recorded exchange: the request, the status, the headers
// that are part of the contract and the exact body.
type contractCase struct {
	Name     string            `json:"name"`
	Request  contractRequest   `json:"request"`
	Status   int               `json:"status"`
	Headers  map[string]string `json:"headers,omitempty"`
	Response json.RawMessage   `json:"response"`
}

type contractRequest struct {
	Method string          `json:"method"`
	Path   string          `json:"path"`
	Body   json.RawMessage `json:"body,omitempty"`
}

func record(t *testing.T, g *ctlRig, name, method, path, body string) contractCase {
	t.Helper()
	got := g.do("worker", method, path, body)
	c := contractCase{Name: name, Request: contractRequest{Method: method, Path: path}, Status: got.code, Response: json.RawMessage(strings.TrimSpace(got.body))}
	if body != "" {
		c.Request.Body = json.RawMessage(body)
	}
	if v := got.header.Get("Idempotent-Replayed"); v != "" {
		c.Headers = map[string]string{"Idempotent-Replayed": v}
	}
	return c
}

// contractCases drives every route through the real router: the request, the
// 200 body, the replay header, the triple cases and every refusal of the
// closed set.
func contractCases(t *testing.T) []contractCase {
	t.Helper()
	var out []contractCase
	g := newCtlRig(t, nil)
	out = append(out, record(t, g, "dispatch ok", http.MethodPost, dispatchPath, dispatchBody))
	g.svc.dispatch = func() (*control.Result, error) {
		return &control.Result{CommandID: ctlCommand, OrderState: "dispatched", EffectState: "none", Replayed: true}, nil
	}
	out = append(out, record(t, g, "dispatch replay", http.MethodPost, dispatchPath, dispatchBody))
	g.svc.cancel = func() (*control.Result, error) {
		return &control.Result{OrderState: "cancelled", EffectState: "none"}, nil
	}
	out = append(out, record(t, g, "cancel before dispatch", http.MethodPost, cancelPath, "{}"))
	for _, tc := range []struct{ name, order, effect string }{
		{"cancel unknown permitted", "unknown", "permitted"},
		{"cancel unknown not_performed", "unknown", "not_performed"},
		{"cancel cancelled none", "cancelled", "none"},
	} {
		g.svc.cancel = func() (*control.Result, error) {
			return &control.Result{CommandID: ctlCommand, OrderState: tc.order, EffectState: tc.effect}, nil
		}
		out = append(out, record(t, g, tc.name, http.MethodPost, cancelPath, "{}"))
	}
	out = append(out, record(t, g, "read command pending", http.MethodGet, commandPath, ""))
	g.svc.readCmd = func() (*control.CommandView, error) {
		return &control.CommandView{CommandID: ctlCommand, OrderRef: ctlOrder, Status: "completed", EffectState: "succeeded",
			Outcome: "succeeded", ProviderEffect: "applied", ErrorCode: "none", ResultDigest: "sha256:aa"}, nil
	}
	out = append(out,
		record(t, g, "read command completed", http.MethodGet, commandPath, ""),
		record(t, g, "read approval", http.MethodGet, approvalPath, ""))

	for _, code := range control.RefusalCodes {
		code := code
		r := newCtlRig(t, nil)
		fail := func() (*control.Result, error) { return nil, glovo.Refuse(code) }
		r.svc.dispatch = fail
		out = append(out, record(t, r, "dispatch refused "+string(code), http.MethodPost, dispatchPath, dispatchBody))
	}
	nr := newCtlRig(t, func(g *GlovoControlRoutes) { g.Dispatcher = nil })
	out = append(out, record(t, nr, "dispatch not ready", http.MethodPost, dispatchPath, dispatchBody))
	bad := newCtlRig(t, nil)
	out = append(out, record(t, bad, "dispatch malformed body", http.MethodPost, dispatchPath, `{"approval_ref":"x"}`))
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func renderContract(t *testing.T) map[string][]byte {
	t.Helper()
	files := map[string][]byte{}
	for _, c := range contractCases(t) {
		var b bytes.Buffer
		enc := json.NewEncoder(&b)
		enc.SetIndent("", "  ")
		if err := enc.Encode(c); err != nil {
			t.Fatal(err)
		}
		files[strings.ReplaceAll(c.Name, " ", "_")+".json"] = b.Bytes()
	}
	var sums []string
	for name, data := range files {
		h := sha256.Sum256(data)
		sums = append(sums, fmt.Sprintf("%s  %s", hex.EncodeToString(h[:]), name))
	}
	sort.Strings(sums)
	files["SHA256SUMS"] = []byte(strings.Join(sums, "\n") + "\n")
	return files
}

// The committed contract is exactly what the real router answers today. Run
// with UPDATE_CONTRACT=1 to rewrite it after a deliberate change.
func TestControlContractMatchesRouter(t *testing.T) {
	want := renderContract(t)
	if os.Getenv("UPDATE_CONTRACT") == "1" {
		if err := os.MkdirAll(contractDir, 0o750); err != nil {
			t.Fatal(err)
		}
		old, _ := filepath.Glob(filepath.Join(contractDir, "*.json"))
		for _, f := range old {
			_ = os.Remove(f)
		}
		for name, data := range want {
			if err := os.WriteFile(filepath.Join(contractDir, name), data, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return
	}
	have, _ := filepath.Glob(filepath.Join(contractDir, "*.json"))
	if len(have) != len(want)-1 {
		t.Fatalf("contract has %d cases, the router produces %d", len(have), len(want)-1)
	}
	for name, data := range want {
		got, err := os.ReadFile(filepath.Join(contractDir, name)) //nolint:gosec // fixed test directory
		if err != nil || !bytes.Equal(got, data) {
			t.Errorf("%s differs from the router (rerun with UPDATE_CONTRACT=1 if deliberate): %v", name, err)
		}
	}
}
