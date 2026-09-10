package mcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestStreamableHTTPHandler_IsStateless pins the wire contract the aggregate
// portal depends on (mctlhq/mctl-api#276): no Mcp-Session-Id is minted on
// initialize, and a request that carries no session header is served. A
// stateful transport would mint an id on the first response and refuse the
// second request, so both halves are needed.
func TestStreamableHTTPHandler_IsStateless(t *testing.T) {
	ts := httptest.NewServer(NewServer("http://localhost:8080", "").NewStreamableHTTPHandler())
	defer ts.Close()

	post := func(body string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	init := post(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`)
	defer init.Body.Close() //nolint:errcheck
	if init.StatusCode != http.StatusOK {
		t.Fatalf("initialize: status %d", init.StatusCode)
	}
	if sid := init.Header.Get("Mcp-Session-Id"); sid != "" {
		t.Fatalf("initialize minted a session id %q; the transport is not stateless", sid)
	}

	list := post(`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`)
	defer list.Body.Close() //nolint:errcheck
	if list.StatusCode != http.StatusOK {
		t.Fatalf("tools/list without a session: status %d", list.StatusCode)
	}
	raw, err := io.ReadAll(list.Body)
	if err != nil {
		t.Fatal(err)
	}
	// The envelope, not the payload: a tool description that happens to
	// contain the word error must not fail a test about sessions. The body
	// may be SSE-framed; the JSON is the last data: line.
	body := string(raw)
	if i := strings.LastIndex(body, "data: "); i >= 0 {
		body = strings.TrimSpace(body[i+len("data: "):])
	}
	var env struct {
		Result *struct {
			Tools []struct{ Name string } `json:"tools"`
		} `json:"result"`
		Error *struct{ Message string } `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &env); err != nil {
		t.Fatalf("tools/list response is not JSON-RPC: %v: %.200s", err, body)
	}
	if env.Error != nil || env.Result == nil {
		t.Fatalf("tools/list without a session was not served: %.200s", body)
	}
	if len(env.Result.Tools) != len(recordedHints) {
		t.Fatalf("tools/list returned %d tools, the record has %d", len(env.Result.Tools), len(recordedHints))
	}

	// GET and DELETE stay served by the transport under stateless mode (a
	// listen stream bound to no session, and a DELETE that terminates
	// nothing) -- measured, not assumed: mcp-go v1.0.0 answers both with 200.
	// What must hold is that neither needs a session id to be accepted.
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		req, err := http.NewRequest(method, ts.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Accept", "application/json, text/event-stream")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close() //nolint:errcheck
		if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusNotFound {
			t.Errorf("%s /mcp without a session: status %d; the transport is demanding a session", method, resp.StatusCode)
		}
	}
}
