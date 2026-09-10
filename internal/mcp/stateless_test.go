package mcp

import (
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
	if body := string(raw); !strings.Contains(body, `"tools"`) || strings.Contains(body, `"error"`) {
		t.Fatalf("tools/list without a session was not served: %.200s", body)
	}
}
