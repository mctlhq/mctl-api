package humaninput

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fixtures in testdata/ were sealed by mctl-agents' own seal_request
// (orchestrator/human_input.py at origin/main 7ed8498) with
// testdata/gen_fixtures.py. Verifying them here is the cross-language
// guarantee: if canonicalJSON drifts from Python's json.dumps by one byte,
// these hashes stop matching.
func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name+".json")) //nolint:gosec // fixed test fixture names
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestParseRequest_VerifiesPythonSealedRequests(t *testing.T) {
	for name, wantID := range map[string]string{
		"ascii_single_choice":     "hir-377a93a48528eb13",
		"unicode_free_text":       "hir-accc85063686b5e0",
		"multi_structured_round2": "hir-ebf62288d90cf1ce",
		// question_hash normalisation edges; see gen_fixtures.py.
		"casefold_edges":  "hir-f543f28e8926bf7f",
		"two_respondents": "hir-88a9e66f157feb60",
	} {
		r, err := ParseRequest(loadFixture(t, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if r.RequestID != wantID {
			t.Fatalf("%s: request_id = %s", name, r.RequestID)
		}
	}
}

// mutate decodes a fixture into a generic map, applies f and re-encodes it.
func mutate(t *testing.T, name string, f func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(loadFixture(t, name), &m); err != nil {
		t.Fatal(err)
	}
	f(m)
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestParseRequest_RejectsAlteredOrMalformed(t *testing.T) {
	cases := map[string]func(m map[string]any){
		"question altered after sealing": func(m map[string]any) { m["question"] = "Which library? (edited)" },
		"actor added after sealing": func(m map[string]any) {
			m["requested_from"].(map[string]any)["actor_refs"] = []any{"github:alice", "github:mallory"}
		},
		"expiry extended": func(m map[string]any) { m["expires_at"] = "2026-09-25T02:00:00Z" },
		"workflow id swapped": func(m map[string]any) {
			m["execution"].(map[string]any)["temporal_workflow_id"] = "dev-loop-mctlhq-x-1"
		},
		"request_id not derived": func(m map[string]any) { m["request_id"] = "hir-0000000000000000" },
		// Outside request_hash, so only its own recomputation catches it.
		"question_hash replaced":  func(m map[string]any) { m["question_hash"] = "sha256:" + strings.Repeat("0", 64) },
		"unknown top-level key":   func(m map[string]any) { m["note"] = "x" },
		"unknown nested key":      func(m map[string]any) { m["response"].(map[string]any)["hint"] = "x" },
		"missing execution":       func(m map[string]any) { delete(m, "execution") },
		"missing request_version": func(m map[string]any) { delete(m, "request_version") },
		"missing release_revision": func(m map[string]any) {
			delete(m["execution"].(map[string]any), "release_revision")
		},
		// Required int in context_snapshot.ExecutionCorrelation, not Optional.
		"null release_revision": func(m map[string]any) {
			m["execution"].(map[string]any)["release_revision"] = nil
		},
		"wrong kind":       func(m map[string]any) { m["kind"] = "HumanInputResponse" },
		"empty actor_refs": func(m map[string]any) { m["requested_from"].(map[string]any)["actor_refs"] = []any{} },
		"bad audience":     func(m map[string]any) { m["requested_from"].(map[string]any)["audience"] = "everyone" },
		"bad context ref":  func(m map[string]any) { m["context_refs"] = []any{"https://evil"} },
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseRequest(mutate(t, "ascii_single_choice", f))
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("accepted: %v", err)
			}
		})
	}
	if _, err := ParseRequest(append(loadFixture(t, "ascii_single_choice"), []byte(`{}`)...)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("trailing data accepted: %v", err)
	}
}

// writePyString against strings Python's json.dumps(ensure_ascii=True)
// produces (values checked with CPython 3.13).
func TestCanonicalJSON_MatchesPythonEscaping(t *testing.T) {
	// Expected values are written with "|" standing for a backslash, so no
	// escape sequence appears literally in this source file.
	for in, want := range map[string]string{
		`a"b\c`:        `"a|"b||c"`,
		"\n\r\t\b\f":   `"|n|r|t|b|f"`,
		"\x00\x1f\x7f": `"|u0000|u001f|u007f"`,
		"<tag> & q":    `"<tag> & q"`,
		"Stra\u00dfe":  `"Stra|u00dfe"`,
		"\u2028":       `"|u2028"`,
		"\U0001f680":   `"|ud83d|ude80"`,
		"\u4e2d\u6587": `"|u4e2d|u6587"`,
	} {
		want = strings.ReplaceAll(want, "|", `\`)
		got, err := canonicalJSON(in)
		if err != nil || string(got) != want {
			t.Errorf("canonicalJSON(%q) = %s, want %s", in, got, want)
		}
	}
	got, _ := canonicalJSON(map[string]any{"b": 1, "a": []string{"x"}, "c": nil, "d": true})
	if string(got) != `{"a":["x"],"b":1,"c":null,"d":true}` {
		t.Errorf("object = %s", got)
	}
}

func TestValidateValue(t *testing.T) {
	choice := ResponseSpec{Type: "single_choice", Options: []string{"A", "B"}}
	multi := ResponseSpec{Type: "multi_choice", Options: []string{"x", "y"}}
	for _, tc := range []struct {
		spec  ResponseSpec
		value any
		ok    bool
	}{
		{ResponseSpec{Type: "free_text"}, "use A", true},
		{ResponseSpec{Type: "free_text"}, "   ", false},
		{ResponseSpec{Type: "free_text"}, 3.0, false},
		{choice, "A", true},
		{choice, "C", false},
		{choice, []any{"A"}, false},
		{multi, []any{"x", "y"}, true},
		{multi, []any{}, false},
		{multi, []any{"x", "q"}, false},
		{ResponseSpec{Type: "structured"}, map[string]any{"k": 1.0}, true},
		{ResponseSpec{Type: "structured"}, "k", false},
	} {
		err := ValidateValue(tc.spec, tc.value)
		if (err == nil) != tc.ok {
			t.Errorf("ValidateValue(%s, %#v) = %v, want ok=%v", tc.spec.Type, tc.value, err, tc.ok)
		}
	}
}

func TestCanRespondIsExact(t *testing.T) {
	r, err := ParseRequest(loadFixture(t, "unicode_free_text"))
	if err != nil {
		t.Fatal(err)
	}
	for ref, want := range map[string]bool{"github:alice": true, "telegram:12345": true, "github:Alice": false, "github:alic": false} {
		if r.CanRespond(ref) != want {
			t.Errorf("CanRespond(%q) = %v", ref, !want)
		}
	}
	if !strings.HasPrefix(r.Question, "Какой") {
		t.Fatal("question not decoded")
	}
}
