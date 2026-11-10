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

package wire

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/mctlhq/mctl-api/internal/glovo"
)

func compile(t *testing.T, name string) *jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	entries, err := schemaFS.ReadDir("schema")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		raw, err := schemaFS.ReadFile("schema/" + e.Name())
		if err != nil {
			t.Fatal(err)
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		if err := c.AddResource("wire/"+e.Name(), doc); err != nil {
			t.Fatal(err)
		}
	}
	s, err := c.Compile("wire/" + name + ".json")
	if err != nil {
		t.Fatalf("compile %s: %v", name, err)
	}
	return s
}

func validate(t *testing.T, name string, v any) {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := compile(t, name).Validate(doc); err != nil {
		t.Fatalf("%s does not validate: %v\n%s", name, err, raw)
	}
}

func TestGoldenMarshalValidates(t *testing.T) {
	now := time.Now().UTC()
	exp := now.Add(time.Hour)
	conn := Connection{Schema: SchemaConnection, ConnectionID: "gcn_01ARZ3NDEKTSV4RRFFQ69G5FAV", State: StatePending,
		InstallRevision: 1, SupersedesID: "gcn_01ARZ3NDEKTSV4RRFFQ69G5FAW", ExpiresAt: &exp, CreatedAt: now, UpdatedAt: now, Replayed: true}
	validate(t, "connection", conn)
	validate(t, "context", Context{Schema: SchemaContext, Tenant: "alpha", PrincipalID: "prn_x", InstallationID: "gin_01ARZ3NDEKTSV4RRFFQ69G5FAV",
		InstallRevision: 2, Connections: []Connection{conn}})
	validate(t, "handoff", Handoff{Schema: SchemaHandoff, ConnectionID: conn.ConnectionID, HandoffRef: "ghr_" + strings.Repeat("a", 64), ExpiresAt: exp})
	validate(t, "connect-request", Empty{Schema: SchemaConnectRequest})
	validate(t, "action-request", Empty{Schema: SchemaActionRequest})
	validate(t, "worker-check-request", WorkerCheckRequest{Schema: SchemaWorkerCheckReq, ConnectionID: conn.ConnectionID, InstallRevision: 1})
	validate(t, "worker-check-response", WorkerCheckResponse{Schema: SchemaWorkerCheckResp, Allowed: true, Tenant: "alpha", OwnerPrincipalID: "prn_x", State: StateActive, ExpiresAt: &exp})
	validate(t, "worker-activate-request", WorkerActivateRequest{Schema: SchemaWorkerActivate, InstallRevision: 1, HandoffRef: "ghr_x"})
	rev := int64(3)
	validate(t, "installation-request", InstallationRequest{Schema: SchemaInstallationReq, InstallRevision: &rev})
	validate(t, "installation-request", InstallationRequest{Schema: SchemaInstallationReq})
	validate(t, "installation", Installation{Schema: SchemaInstallation, Tenant: "alpha", InstallationID: "gin_01ARZ3NDEKTSV4RRFFQ69G5FAV", InstallRevision: 1, State: "installed"})
}

func TestSchemasRejectUnknownFieldAndWrongSchema(t *testing.T) {
	s := compile(t, "connect-request")
	for _, body := range []string{
		`{"schema":"glovo-connection/v1alpha1.ConnectRequest","tenant":"x"}`,
		`{"schema":"glovo-connection/v1alpha1.Connection"}`,
		`{}`,
	} {
		doc, _ := jsonschema.UnmarshalJSON(strings.NewReader(body))
		if err := s.Validate(doc); err == nil {
			t.Fatalf("%s validated", body)
		}
	}
}

func TestEveryRefusalCodeIsMappedAndValidates(t *testing.T) {
	s := compile(t, "error")
	var codes []string
	for _, c := range glovo.Codes() {
		codes = append(codes, string(c))
		rec := httptest.NewRecorder()
		glovo.WriteError(rec, glovo.Refuse(c))
		if rec.Code != glovo.Status(c) || rec.Code < 400 {
			t.Fatalf("%s: status %d", c, rec.Code)
		}
		doc, err := jsonschema.UnmarshalJSON(rec.Body)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Validate(doc); err != nil {
			t.Fatalf("%s: %v", c, err)
		}
		if strings.Contains(rec.Body.String(), `"schema"`) {
			t.Fatalf("%s: refusal body has a schema field", c)
		}
	}
	// The schema enum is exactly the closed set.
	raw, _ := schemaFS.ReadFile("schema/error.json")
	var doc struct {
		Properties struct {
			Error struct {
				Enum []string `json:"enum"`
			} `json:"error"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	got := doc.Properties.Error.Enum
	sort.Strings(got)
	sort.Strings(codes)
	if strings.Join(got, ",") != strings.Join(codes, ",") {
		t.Fatalf("error.json enum differs from glovo.Codes():\n%v\n%v", got, codes)
	}
}

func TestPublicStateMapsEveryStoreState(t *testing.T) {
	want := map[glovo.ConnectionState]string{
		glovo.PendingHandoff: StatePending, glovo.PendingProvider: StatePending, glovo.Active: StateActive,
		glovo.Expired: StateExpired, glovo.Failed: StateFailed, glovo.Revoked: StateRevoked,
		glovo.ConnectionState("bogus"): StateFailed,
	}
	for in, out := range want {
		if got := PublicState(in); got != out {
			t.Fatalf("%s: got %s want %s", in, got, out)
		}
	}
}

func TestDecodeStrict(t *testing.T) {
	dec := func(body string, optional bool) *glovo.Error {
		r := httptest.NewRequest("POST", "/", strings.NewReader(body))
		var e Empty
		return Decode(httptest.NewRecorder(), r, &e, SchemaConnectRequest, optional)
	}
	if e := dec(`{"schema":"`+SchemaConnectRequest+`"}`, false); e != nil {
		t.Fatalf("valid: %v", e)
	}
	for name, body := range map[string]string{
		"unknown field": `{"schema":"` + SchemaConnectRequest + `","tenant":"alpha"}`,
		"wrong schema":  `{"schema":"x"}`,
		"trailing":      `{"schema":"` + SchemaConnectRequest + `"} {}`,
		"not json":      `nope`,
		"too big":       `{"schema":"` + SchemaConnectRequest + `","pad":"` + strings.Repeat("a", MaxBodyBytes) + `"}`,
	} {
		if e := dec(body, true); e == nil || e.Code != glovo.CodeInvalidRequest {
			t.Fatalf("%s: got %v", name, e)
		}
	}
	if e := dec("", false); e == nil {
		t.Fatal("empty body accepted when required")
	}
	if e := dec("", true); e != nil {
		t.Fatalf("empty optional body: %v", e)
	}
}
