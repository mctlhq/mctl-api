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

package bridge

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/glovo/basket"
)

const v2Dir = "schema/v1alpha2"

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func readSums(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(v2Dir, "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			t.Fatalf("bad SHA256SUMS line %q", line)
		}
		m[f[1]] = f[0]
	}
	return m
}

// T1: every vendored v1alpha2 file matches its SHA256SUMS line and SHA256SUMS
// itself matches the pin in PROVENANCE; a one-byte change fails.
func TestVendoredV1alpha2MatchesProvenance(t *testing.T) {
	sums := readSums(t)
	prov, err := os.ReadFile(filepath.Join(v2Dir, "PROVENANCE"))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(v2Dir, "SHA256SUMS"))
	if !strings.Contains(string(prov), sum(raw)) {
		t.Fatalf("PROVENANCE does not pin sha256 of SHA256SUMS (%s)", sum(raw))
	}
	n := 0
	err = filepath.Walk(v2Dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(v2Dir, path)
		if rel == "SHA256SUMS" || rel == "PROVENANCE" {
			return nil
		}
		want, ok := sums[filepath.ToSlash(rel)]
		if !ok {
			t.Errorf("%s is vendored but not in SHA256SUMS", rel)
			return nil
		}
		b, rerr := os.ReadFile(path) //nolint:gosec // test reads vendored fixtures
		if rerr != nil {
			return rerr
		}
		if got := sum(b); got != want {
			t.Errorf("%s: sha256 %s, want %s", rel, got, want)
		}
		n++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n < 40 {
		t.Fatalf("only %d vendored files checked", n)
	}
	// The mutation step: one flipped byte is detected.
	b, _ := os.ReadFile(filepath.Join(v2Dir, "read-result.schema.json"))
	b[0] ^= 1
	if sum(b) == sums["read-result.schema.json"] {
		t.Fatal("a one-byte change went undetected")
	}
}

// The approval-basket schema the v1alpha2 schemas $ref is #988's copy; it must
// be the byte-identical file SHA256SUMS names, and all four schemas compile.
func TestApprovalBasketRefResolves(t *testing.T) {
	raw, err := basket.SchemaJSON()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := sum(raw), readSums(t)["approval-basket.schema.json"]; got != want {
		t.Fatalf("approval-basket.schema.json sha256 %s, want %s", got, want)
	}
	if err := compileSchemas(); err != nil {
		t.Fatal(err)
	}
}

func v2fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(v2Dir, "fixtures", name)) //nolint:gosec // test fixture path
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// T2: every valid fixture is accepted; every invalid fixture is refused, by
// the stage that owns its reason.
func TestV1alpha2Fixtures(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(v2Dir, "fixtures", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	ran := 0
	for _, f := range files {
		name := filepath.Base(f)
		raw := v2fixture(t, name)
		valid := strings.Contains(name, ".valid.") || name == "read-result.at-cap.json"
		// The size cap of the whole body belongs to the HTTP handler
		// (bridgeMaxBody = 16384): at-cap passes it, over-cap is a schema-valid
		// document refused there as invalid_document.
		if name == "read-result.over-cap.json" {
			if len(raw) != 16385 {
				t.Errorf("%s is %d bytes, want 16385", name, len(raw))
			}
			continue
		}
		if name == "read-result.at-cap.json" && len(raw) != 16384 {
			t.Errorf("%s is %d bytes, want 16384", name, len(raw))
		}
		var err error
		switch {
		case strings.HasPrefix(name, "read-command."):
			if err = rawCheck(raw); err == nil {
				err = ValidateReadCommand(raw)
			}
		case strings.HasPrefix(name, "read-result."):
			var r *ReadResultDoc
			if r, err = ParseReadResult(raw); err == nil && r.Outcome == "succeeded" {
				_, err = r.canonicalPayload()
			}
		case strings.HasPrefix(name, "command-place-order-fake."):
			err = ValidateWriteV2Command(raw)
		case strings.HasPrefix(name, "claim-response."):
			err = ValidateClaimResponse(raw)
		default:
			continue // approval-basket fixtures are #988's
		}
		ran++
		if valid && err != nil {
			t.Errorf("%s: want valid, got %v", name, err)
		}
		if !valid && err == nil {
			t.Errorf("%s: want refused, accepted", name)
		}
	}
	if ran < 40 {
		t.Fatalf("only %d fixtures ran", ran)
	}
}

// Every must-reject entry that applies to a result or command is refused.
func TestV1alpha2MustReject(t *testing.T) {
	raw, err := os.ReadFile("../jcs/testdata/must-reject.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Entries []struct {
			Name    string
			Applies []string
			Raw     string
		} `json:"entries"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	ran := 0
	for _, e := range f.Entries {
		for _, a := range e.Applies {
			var err error
			switch a {
			case "read-result":
				_, err = ParseReadResult([]byte(e.Raw))
			case "read-command":
				if err = rawCheck([]byte(e.Raw)); err == nil {
					err = ValidateReadCommand([]byte(e.Raw))
				}
			default:
				continue
			}
			ran++
			if err == nil {
				t.Errorf("%s (%s): accepted", e.Name, a)
			} else if !errors.Is(err, ErrInvalidDocument) {
				t.Errorf("%s (%s): %v is not invalid_document", e.Name, a, err)
			}
		}
	}
	if ran == 0 {
		t.Fatal("no must-reject entry ran")
	}
}

// T3b: Go leg of pattern-parity.json over the vendored read schemas.
func TestV1alpha2PatternParity(t *testing.T) {
	raw, err := os.ReadFile("../glovo/basket/contract/pattern-parity.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Cases []struct {
			ID, Schema, Pointer string
			Accept, Reject      []string
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	ran := 0
	for _, c := range f.Cases {
		if c.Schema != "read-result.schema.json" && c.Schema != "read-command.schema.json" {
			continue
		}
		sraw, err := os.ReadFile(filepath.Join(v2Dir, c.Schema))
		if err != nil {
			t.Fatal(err)
		}
		var cur any
		if err := json.Unmarshal(sraw, &cur); err != nil {
			t.Fatal(err)
		}
		for _, part := range strings.Split(strings.TrimPrefix(c.Pointer, "/"), "/") {
			m, ok := cur.(map[string]any)
			if !ok {
				t.Fatalf("%s: bad pointer %s", c.ID, c.Pointer)
			}
			cur = m[part]
		}
		pat, ok := cur.(string)
		if !ok {
			t.Fatalf("%s: no pattern at %s", c.ID, c.Pointer)
		}
		re := regexp.MustCompile(pat)
		for _, s := range c.Accept {
			if !re.MatchString(s) {
				t.Errorf("%s: %q must match", c.ID, s)
			}
		}
		for _, s := range c.Reject {
			if re.MatchString(s) {
				t.Errorf("%s: %q must not match", c.ID, s)
			}
		}
		ran++
	}
	if ran == 0 {
		t.Fatal("no read pattern case ran")
	}
}

// T3: this slice has no canonicalizer of its own; it imports internal/jcs.
func TestNoOwnCanonicalizer(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, _ := os.ReadFile(f) //nolint:gosec // test enumerates package sources
		for _, bad := range []string{"func canonical", "func Canonical", "utf16.Encode", "sort.Strings(keys)"} {
			if strings.Contains(string(b), bad) {
				t.Errorf("%s contains %q: canonicalization belongs to internal/jcs", f, bad)
			}
		}
	}
}

func readRow(kind string) *cmdRow {
	return &cmdRow{
		CommandID: "cmd_01HZZZZZZZZZZZZZZZZZZZZZZZ", TenantRef: "tnr_0123456789abcdef0123", PrincipalRef: "prr_0123456789abcdef0123",
		ConnectionRef: "gcn_0123456789abcdef0123", ProviderRef: "glovo", Kind: kind, Attempt: 1,
		CommandNonce: "AAAAAAAAAAAAAAAAAAAAAA", CreatedAt: time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC),
		ExpiresAt: time.Date(2026, 11, 9, 10, 5, 0, 0, time.UTC), TTLSeconds: 300, Payload: json.RawMessage(`{}`),
		WireVersion: WireV1alpha2, ReadRequestID: "rdq_01HYYYYYYYYYYYYYYYYYYYYYYY", InstallRevisionRef: "irv_0123456789abcdef0123",
	}
}

// T4b: the read projection carries install_revision_ref and validates against
// the vendored read-command schema; without the ref it does not.
func TestReadProjection(t *testing.T) {
	row := readRow(KindReadBasket)
	row.LeaseToken = "lt_0123456789abcdef0123"
	raw, err := row.projection(true)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["install_revision_ref"] != "irv_0123456789abcdef0123" || doc["schema_version"] != WireV1alpha2 {
		t.Fatalf("projection = %s", raw)
	}
	for _, forbidden := range []string{"execution_id", "work_item_id", "order_ref", "workflow_id", "approval_ref", "intent_hash"} {
		if _, ok := doc[forbidden]; ok {
			t.Errorf("read projection carries %s", forbidden)
		}
	}
	row.InstallRevisionRef = "" // the decimal revision is never emitted as the ref
	if _, err := row.projection(false); !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("projection without the ref: %v", err)
	}
	hist := readRow(KindReadHistory)
	hist.Payload = json.RawMessage(`{"limit":20}`)
	if _, err := hist.projection(false); err != nil {
		t.Fatal(err)
	}
	hist.Payload = json.RawMessage(`{"limit":21}`)
	if _, err := hist.projection(false); err == nil {
		t.Fatal("params outside the schema were projected")
	}
}

// T4e: the v1alpha2 place_order_fake projection follows the row's wire version.
func TestWriteV2Projection(t *testing.T) {
	basketPayload := func() json.RawMessage {
		var d struct {
			Payload json.RawMessage `json:"payload"`
		}
		if err := json.Unmarshal(v2fixture(t, "command-place-order-fake.valid.json"), &d); err != nil {
			t.Fatal(err)
		}
		return d.Payload
	}()
	row := &cmdRow{
		CommandID: "cmd_01HZZZZZZZZZZZZZZZZZZZZZZZ", ExecutionID: "we_0123456789abcdef0123", WorkItemID: "wi_0123456789abcdef0123",
		TenantRef: "tnr_0123456789abcdef0123", PrincipalRef: "prr_0123456789abcdef0123", OrderRef: "ordr_0123456789abcdef0123",
		ConnectionRef: "gcn_0123456789abcdef0123", ApprovalRef: "aar_0123456789abcdef0123", ProviderRef: "glovo",
		Kind: KindPlaceOrderFake, Attempt: 1, IntentHash: "sha256:" + strings.Repeat("0", 64), CommandNonce: "AAAAAAAAAAAAAAAAAAAAAA",
		CreatedAt: time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC), ExpiresAt: time.Date(2026, 11, 8, 10, 10, 0, 0, time.UTC),
		TTLSeconds: 600, Payload: basketPayload, WireVersion: WireV1alpha2,
	}
	raw, err := row.projection(false)
	if err != nil {
		t.Fatalf("v2 write: %v", err)
	}
	if !strings.Contains(string(raw), `"schema_version":"`+WireV1alpha2+`"`) {
		t.Fatalf("not v1alpha2: %s", raw)
	}
	row.WireVersion = "" // the approval basket under v1alpha1 is refused by the closed payload
	if _, err := row.projection(false); !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("basket under v1alpha1: %v", err)
	}
	row.WireVersion, row.Payload = WireV1alpha2, json.RawMessage(`{"item_codes":["FAKE-1"],"quantity_total":1}`)
	if _, err := row.projection(false); !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("v1alpha1 payload under v1alpha2: %v", err)
	}
}

func TestEnqueueInputWireVersion(t *testing.T) {
	base := EnqueueInput{
		ExecutionID: "we_0123456789abcdef0123", WorkItemID: "wi_0123456789abcdef0123", WorkflowID: "wf", Tenant: "t",
		OwnerPrincipalID: "o", TenantRef: "tnr_0123456789abcdef0123", PrincipalRef: "prr_0123456789abcdef0123",
		OrderRef: "ordr_0123456789abcdef0123", ConnectionRef: "gcn_0123456789abcdef0123", InstallRevision: "1",
		ProviderRef: "glovo", Attempt: 1, OperationKey: "k", IntentHash: "sha256:" + strings.Repeat("0", 64),
	}
	for _, kind := range []string{KindQuote, KindCancelOrder, KindReadStatus} {
		in := base
		in.Kind, in.WireVersion, in.ApprovalRef = kind, WireV1alpha2, "aar_0123456789abcdef0123"
		if err := in.validate(); !errors.Is(err, ErrInvalidDocument) {
			t.Errorf("v1alpha2 on %s: %v", kind, err)
		}
	}
	in := base
	in.Kind, in.WireVersion, in.ApprovalRef = KindPlaceOrderFake, WireV1alpha2, "aar_0123456789abcdef0123"
	if err := in.validate(); err != nil {
		t.Fatal(err)
	}
	in.WireVersion = "bridge.mctl.ai/v9"
	if err := in.validate(); !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("unknown wire version: %v", err)
	}
}

// T4h (unit part): envelope versions and the claim response schema.
func TestClaimEnvelopeVersions(t *testing.T) {
	if got := (Caller{}).ClaimEnvelopeVersion(); got != SchemaVersion {
		t.Fatalf("nil versions: %s", got)
	}
	if got := (Caller{Versions: []string{WireV1alpha1}}).ClaimEnvelopeVersion(); got != SchemaVersion {
		t.Fatalf("v1alpha1 only: %s", got)
	}
	if got := (Caller{Versions: []string{WireV1alpha1, WireV1alpha2}}).ClaimEnvelopeVersion(); got != ClaimEnvelopeV1alpha2 {
		t.Fatalf("v1alpha2: %s", got)
	}
	if v := (Caller{}).wireVersions(); len(v) != 1 || v[0] != WireV1alpha1 {
		t.Fatalf("default versions: %v", v)
	}
}

// T7/T8 (pure part): pipeline checks that need no database.
func TestReadResultPipeline(t *testing.T) {
	for _, name := range []string{"read-result.history.valid.json", "read-result.preview.valid.json", "read-result.basket.valid.json", "read-result.at-cap.json"} {
		doc, err := parseAnyResult(v2fixture(t, name))
		if err != nil || doc.v2 == nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := doc.v2.canonicalPayload(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		d1, err := doc.v2.Digest()
		if err != nil {
			t.Fatal(err)
		}
		// The replay digest ignores the lease token.
		other := strings.Replace(string(v2fixture(t, name)), "lt_0123456789abcdef0123", "lt_ffffffffffffffffffff", 1)
		d2doc, err := parseAnyResult([]byte(other))
		if err != nil {
			t.Fatal(err)
		}
		if d2, _ := d2doc.v2.Digest(); d2 != d1 {
			t.Errorf("%s: digest depends on the lease token", name)
		}
	}
	doc, _ := parseAnyResult(v2fixture(t, "read-result.digest-mismatch.json"))
	if _, err := doc.v2.canonicalPayload(); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("digest mismatch: %v", err)
	}
	big := &ReadResultDoc{Payload: json.RawMessage(`{"a":"` + strings.Repeat("x", MaxReadPayload) + `"}`)}
	if _, err := big.canonicalPayload(); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("over cap: %v", err)
	}
	for _, bad := range []string{"read-result.with-binding-echo.json", "read-result.extra-field.json", "read-result.quantity-float.json", "read-result.failed-with-payload.json"} {
		if _, err := parseAnyResult(v2fixture(t, bad)); !errors.Is(err, ErrInvalidDocument) {
			t.Errorf("%s: %v", bad, err)
		}
	}
	// A v1alpha1 document still takes the v1alpha1 path.
	if d, err := parseAnyResult(mustRead(t, "schema/testdata/result.valid.json")); err != nil || d.v1 == nil {
		t.Fatalf("v1alpha1 result: %v", err)
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p) //nolint:gosec // test fixture path
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestNewSentinelCodes(t *testing.T) {
	for err, want := range map[error]string{
		ErrPayloadTooLarge: "payload_too_large", ErrReadUnavailable: "read_unavailable", ErrReadNotAuthorized: "read_not_authorized",
	} {
		if got := Code(err); got != want {
			t.Errorf("Code(%v) = %q, want %q", err, got, want)
		}
	}
}

func TestSetReadResultTTLClamps(t *testing.T) {
	s := &Store{}
	for in, want := range map[time.Duration]int{0: 300, -1: 300, time.Millisecond: 1, 5 * time.Second: 5, time.Hour: 300} {
		s.SetReadResultTTL(in)
		if got := s.readTTLSeconds(); got != want {
			t.Errorf("ttl %v -> %d, want %d", in, got, want)
		}
	}
}

func TestDenyConnectionChecker(t *testing.T) {
	s := &Store{}
	if _, err := s.currentChecker().Live(t.Context(), "t", "p"); err == nil {
		t.Fatal("default checker must deny")
	}
}

// parseAnyResult picks a result's schema by its schema_version. The
// bytes.Contains(WireV1alpha2) marker only decides whether the raw-bytes
// pre-check runs early: it never forces a document onto the v1alpha2 path.
func TestParseAnyResultMarkerFallback(t *testing.T) {
	v1 := string(mustRead(t, "schema/testdata/result.valid.json"))
	// A v1alpha1 result that merely mentions the v1alpha2 string in a free text
	// field still parses as v1alpha1.
	withMention := strings.Replace(v1, `"error_code": "none"`, `"error_code": "none", "error_detail": "retry on `+WireV1alpha2+`"`, 1)
	if d, err := parseAnyResult([]byte(withMention)); err != nil || d.v1 == nil || d.v2 != nil {
		t.Fatalf("v1alpha1 body mentioning the marker: %+v %v", d, err)
	}
	// A v1alpha2 body that fails the pre-check (duplicate key) is refused by
	// the pre-check, as invalid_document.
	dup := strings.Replace(string(v2fixture(t, "read-result.history.valid.json")), `"attempt": 1,`, `"attempt": 1, "attempt": 1,`, 1)
	if _, err := parseAnyResult([]byte(dup)); !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("duplicate key in a v1alpha2 body: %v", err)
	}
	// Bytes that are not JSON but contain the marker are invalid_document too.
	if _, err := parseAnyResult([]byte(`{"x": ` + WireV1alpha2 + ``)); !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("malformed body with the marker: %v", err)
	}
	// A v1alpha1 body that fails the pre-check while mentioning the marker is
	// not claimed by the v1alpha2 path: it is judged by the v1alpha1 schema.
	dupV1 := strings.Replace(withMention, `"attempt": 1,`, `"attempt": 1, "attempt": 1,`, 1)
	if d, err := parseAnyResult([]byte(dupV1)); d != nil && d.v2 != nil {
		t.Fatalf("v1alpha1 body routed to v1alpha2: %v", err)
	}
}
