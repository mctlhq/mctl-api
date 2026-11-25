package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
)

// TestStatsViewHostHarness loads the embedded statistics console in headless
// Chrome and plays the MCP Apps host on the other side of postMessage.
//
//	go test -count=1 -run TestStatsViewHostHarness ./internal/mcp/
//
// Chrome is taken from CHROME_PATH or from PATH (google-chrome, chromium).
// The test skips when no browser is installed, unless MCTL_REQUIRE_BROWSER=1,
// which CI sets so a missing browser fails the job instead of skipping.
func TestStatsViewHostHarness(t *testing.T) {
	bin := findChrome(t)
	srv := httptest.NewServer(statsBrowserMux())
	defer srv.Close()

	opts := make([]chromedp.ExecAllocatorOption, 0, len(chromedp.DefaultExecAllocatorOptions)+3)
	opts = append(opts, chromedp.DefaultExecAllocatorOptions[:]...)
	opts = append(opts, chromedp.ExecPath(bin), chromedp.NoSandbox, chromedp.Flag("disable-dev-shm-usage", true))
	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer allocCancel()
	tabCtx, tabCancel := chromedp.NewContext(allocCtx)
	defer tabCancel()
	ctx, cancel := context.WithTimeout(tabCtx, 60*time.Second)
	defer cancel()

	t.Run("handshakeThenResult", func(t *testing.T) {
		openStatsHost(t, ctx, srv.URL, 1400, 900)
		initMsg := waitHostMethod(t, ctx, "ui/initialize", 1)
		params, _ := initMsg["params"].(map[string]any)
		if params["protocolVersion"] != "2026-01-26" {
			t.Fatalf("protocolVersion = %#v", params["protocolVersion"])
		}
		appInfo, _ := params["appInfo"].(map[string]any)
		if appInfo["name"] != "mctl-stats-app" {
			t.Fatalf("appInfo = %#v", params["appInfo"])
		}
		if _, ok := params["appCapabilities"].(map[string]any); !ok {
			t.Fatalf("appCapabilities = %#v", params["appCapabilities"])
		}
		if hostMethodCount(t, ctx, "ui/notifications/initialized") != 0 {
			t.Fatal("initialized arrived before the host answered ui/initialize")
		}
		if text := viewText(t, ctx, "hdr-asof"); !strings.Contains(text, "Встроенный снимок") {
			t.Fatalf("embedded snapshot was not rendered before tool-result: %q", text)
		}

		hostPost(t, ctx, map[string]any{
			"jsonrpc": "2.0",
			"id":      initMsg["id"],
			"result":  statsInitResult("2026-01-26", "dark"),
		})
		waitHostMethod(t, ctx, "ui/notifications/initialized", 1)
		hostPost(t, ctx, map[string]any{"jsonrpc": "2.0", "id": 77, "method": "ping"})
		hostPost(t, ctx, map[string]any{"jsonrpc": "2.0", "id": 78, "method": "ui/resource-teardown", "params": map[string]any{"reason": "test"}})
		waitHostReply(t, ctx, 77)
		waitHostReply(t, ctx, 78)
		if text := viewText(t, ctx, "hdr-asof"); !strings.Contains(text, "Встроенный снимок") {
			t.Fatalf("initialized waited on tool-result: %q", text)
		}
		if theme := viewAttr(t, ctx, "data-theme"); theme != "dark" {
			t.Fatalf("data-theme = %q", theme)
		}
		if got := viewStyle(t, ctx, "--color-background-primary"); got != "#080c14" {
			t.Fatalf("host style variable = %q", got)
		}

		dash := statsBrowserSnapshot("mashkovd")
		hostPost(t, ctx, map[string]any{
			"jsonrpc": "2.0",
			"method":  "ui/notifications/tool-input",
			"params":  map[string]any{"arguments": map[string]any{"team": "labs"}},
		})
		hostPost(t, ctx, map[string]any{
			"jsonrpc": "2.0",
			"method":  "ui/notifications/tool-result",
			"params": map[string]any{
				"content":           []any{map[string]any{"type": "text", "text": "summary"}},
				"structuredContent": dash,
			},
		})
		waitViewText(t, ctx, "hdr-user", "mashkovd")
		if input := viewJS(t, ctx, `return document.getElementById("view").contentWindow.__mctlApps.lastToolInput.team || ""`); input != "labs" {
			t.Fatalf("tool-input = %q", input)
		}
		size := waitHostMethod(t, ctx, "ui/notifications/size-changed", 1)
		sizeParams, _ := size["params"].(map[string]any)
		if numField(sizeParams["width"]) <= 0 || numField(sizeParams["height"]) <= 0 {
			t.Fatalf("size-changed = %#v", sizeParams)
		}
		if reason := viewJS(t, ctx, statsLayoutJS(true)); reason != "" {
			t.Fatalf("desktop layout: %s", reason)
		}

		if err := chromedp.Run(ctx, chromedp.EmulateViewport(420, 800)); err != nil {
			t.Fatal(err)
		}
		if reason := viewJS(t, ctx, statsLayoutJS(false)); reason != "" {
			t.Fatalf("mobile layout: %s", reason)
		}

		hostPost(t, ctx, map[string]any{
			"jsonrpc": "2.0",
			"method":  "ui/notifications/host-context-changed",
			"params":  map[string]any{"theme": "light", "safeAreaInsets": map[string]any{"top": 4, "right": 0, "bottom": 0, "left": 0}},
		})
		waitViewJS(t, ctx, `document.getElementById("view").contentDocument.documentElement.getAttribute("data-theme")==="light" && document.getElementById("view").contentDocument.documentElement.style.getPropertyValue("--safe-top")==="4px"`)

		before := hostMethodCount(t, ctx, "tools/call")
		if err := chromedp.Run(ctx, chromedp.Evaluate(`document.getElementById("view").contentDocument.getElementById("btn-bridge-refresh").click(), true`, new(bool))); err != nil {
			t.Fatal(err)
		}
		call := waitHostMethod(t, ctx, "tools/call", before+1)
		callParams, _ := call["params"].(map[string]any)
		if callParams["name"] != "mctl_stats_dashboard" {
			t.Fatalf("tools/call = %#v", callParams)
		}
		args, _ := callParams["arguments"].(map[string]any)
		if args["team"] != "labs" {
			t.Fatalf("refresh arguments = %#v", args)
		}
		refreshed := statsBrowserSnapshot("refreshed-user")
		hostPost(t, ctx, map[string]any{
			"jsonrpc": "2.0",
			"id":      call["id"],
			"result": map[string]any{
				"content":           []any{map[string]any{"type": "text", "text": "refreshed"}},
				"structuredContent": refreshed,
			},
		})
		// The spec's interactive phase also pushes tool-input then tool-result
		// after the tools/call the view itself made. Same payload, so the
		// second apply stays on the refreshed snapshot.
		hostPost(t, ctx, map[string]any{
			"jsonrpc": "2.0",
			"method":  "ui/notifications/tool-input",
			"params":  map[string]any{"arguments": map[string]any{"team": "labs"}},
		})
		hostPost(t, ctx, map[string]any{
			"jsonrpc": "2.0",
			"method":  "ui/notifications/tool-result",
			"params":  map[string]any{"structuredContent": refreshed},
		})
		waitViewText(t, ctx, "hdr-user", "refreshed-user")
	})

	t.Run("toolResultBeforeInitialize", func(t *testing.T) {
		openStatsHost(t, ctx, srv.URL, 1100, 800)
		initMsg := waitHostMethod(t, ctx, "ui/initialize", 1)
		hostPost(t, ctx, map[string]any{
			"jsonrpc": "2.0",
			"method":  "ui/notifications/tool-input",
			"params":  map[string]any{"arguments": map[string]any{}},
		})
		hostPost(t, ctx, map[string]any{
			"jsonrpc": "2.0",
			"method":  "ui/notifications/tool-result",
			"params":  map[string]any{"structuredContent": statsBrowserSnapshot("early-user")},
		})
		waitViewText(t, ctx, "hdr-user", "early-user")
		if hostMethodCount(t, ctx, "ui/notifications/initialized") != 0 {
			t.Fatal("tool-result completed the handshake on its own")
		}
		hostPost(t, ctx, map[string]any{
			"jsonrpc": "2.0",
			"id":      initMsg["id"],
			"result":  statsInitResult("2026-01-26", "dark"),
		})
		waitHostMethod(t, ctx, "ui/notifications/initialized", 1)
		if text := viewText(t, ctx, "hdr-user"); !strings.Contains(text, "early-user") {
			t.Fatalf("early tool-result was dropped: %q", text)
		}
	})

	t.Run("protocolFallback", func(t *testing.T) {
		openStatsHost(t, ctx, srv.URL, 800, 600)
		first := waitHostMethod(t, ctx, "ui/initialize", 1)
		if params, _ := first["params"].(map[string]any); params["protocolVersion"] != "2026-01-26" {
			t.Fatalf("first version = %#v", first["params"])
		}
		hostPost(t, ctx, map[string]any{
			"jsonrpc": "2.0",
			"id":      first["id"],
			"error": map[string]any{
				"code":    -32602,
				"message": "Unsupported protocol version",
				"data":    map[string]any{"supported": []string{"2025-11-21"}},
			},
		})
		second := waitHostMethod(t, ctx, "ui/initialize", 2)
		params, _ := second["params"].(map[string]any)
		if params["protocolVersion"] != "2025-11-21" {
			t.Fatalf("fallback version = %#v", params["protocolVersion"])
		}
		hostPost(t, ctx, map[string]any{
			"jsonrpc": "2.0",
			"id":      second["id"],
			"result":  statsInitResult("2025-11-21", "light"),
		})
		waitHostMethod(t, ctx, "ui/notifications/initialized", 1)
		if got := viewJS(t, ctx, `return document.getElementById("view").contentWindow.__mctlApps.protocolVersion || ""`); got != "2025-11-21" {
			t.Fatalf("negotiated version = %q", got)
		}
		if theme := viewAttr(t, ctx, "data-theme"); theme != "light" {
			t.Fatalf("fallback theme = %q", theme)
		}
	})
}

func findChrome(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("CHROME_PATH"); p != "" {
		return p
	}
	for _, name := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	if os.Getenv("MCTL_REQUIRE_BROWSER") == "1" {
		t.Fatal("headless Chrome is required but was not found")
	}
	t.Skip("headless Chrome not installed; set CHROME_PATH to run the MCP Apps host harness")
	return ""
}

func statsBrowserMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/view.html", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if _, err := io.WriteString(w, statsViewHTML); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
	mux.HandleFunc("/host.html", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if _, err := io.WriteString(w, statsHostPage); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
	return mux
}

const statsHostPage = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>MCP Apps host harness</title>
<style>html,body{margin:0;height:100%}iframe{width:100%;height:100%;border:0}</style>
<script>
window.__hostLog = [];
window.addEventListener("message", (ev) => {
  const frame = document.getElementById("view");
  if (!frame || ev.source !== frame.contentWindow) return;
  const msg = ev.data;
  if (!msg || msg.jsonrpc !== "2.0") return;
  window.__hostLog.push(msg);
});
window.__hostPost = (msg) => {
  const frame = document.getElementById("view");
  frame.contentWindow.postMessage(msg, "*");
  return true;
};
</script>
</head>
<body><iframe id="view" src="/view.html"></iframe></body>
</html>
`

func openStatsHost(t *testing.T, ctx context.Context, base string, width, height int64) {
	t.Helper()
	if err := chromedp.Run(ctx,
		chromedp.EmulateViewport(width, height),
		chromedp.Navigate(base+"/host.html"),
	); err != nil {
		t.Fatal(err)
	}
}

func hostPost(t *testing.T, ctx context.Context, msg any) {
	t.Helper()
	raw, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	var ok bool
	if err := chromedp.Run(ctx, chromedp.Evaluate("window.__hostPost("+string(raw)+")", &ok)); err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("host post was not delivered")
	}
}

func hostLog(t *testing.T, ctx context.Context) []map[string]any {
	t.Helper()
	var raw string
	if err := chromedp.Run(ctx, chromedp.Evaluate(`JSON.stringify(window.__hostLog)`, &raw)); err != nil {
		t.Fatal(err)
	}
	var msgs []map[string]any
	if err := json.Unmarshal([]byte(raw), &msgs); err != nil {
		t.Fatalf("host log: %v body %s", err, raw)
	}
	return msgs
}

func hostMethodCount(t *testing.T, ctx context.Context, method string) int {
	t.Helper()
	n := 0
	for _, msg := range hostLog(t, ctx) {
		if msg["method"] == method {
			n++
		}
	}
	return n
}

func waitHostReply(t *testing.T, ctx context.Context, id float64) map[string]any {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for {
		for _, msg := range hostLog(t, ctx) {
			if numField(msg["id"]) != id || msg["method"] != nil {
				continue
			}
			if _, ok := msg["result"]; ok {
				return msg
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for reply %v; log=%s", id, mustJSON(hostLog(t, ctx)))
		}
		time.Sleep(40 * time.Millisecond)
	}
}

func waitHostMethod(t *testing.T, ctx context.Context, method string, n int) map[string]any {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for {
		var found []map[string]any
		for _, msg := range hostLog(t, ctx) {
			if msg["method"] == method {
				found = append(found, msg)
			}
		}
		if len(found) >= n {
			return found[n-1]
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s #%d; log=%s", method, n, mustJSON(hostLog(t, ctx)))
		}
		time.Sleep(40 * time.Millisecond)
	}
}

func viewJS(t *testing.T, ctx context.Context, js string) string {
	t.Helper()
	var out string
	if err := chromedp.Run(ctx, chromedp.Evaluate("(() => { "+js+" })()", &out)); err != nil {
		t.Fatalf("view js: %v\n%s", err, js)
	}
	return out
}

func viewText(t *testing.T, ctx context.Context, id string) string {
	t.Helper()
	return viewJS(t, ctx, fmt.Sprintf(`return document.getElementById("view").contentDocument.getElementById(%q).textContent`, id))
}

func viewAttr(t *testing.T, ctx context.Context, name string) string {
	t.Helper()
	return viewJS(t, ctx, fmt.Sprintf(`return document.getElementById("view").contentDocument.documentElement.getAttribute(%q) || ""`, name))
}

func viewStyle(t *testing.T, ctx context.Context, prop string) string {
	t.Helper()
	return viewJS(t, ctx, fmt.Sprintf(`return document.getElementById("view").contentDocument.documentElement.style.getPropertyValue(%q)`, prop))
}

func waitViewText(t *testing.T, ctx context.Context, id, needle string) {
	t.Helper()
	waitViewJS(t, ctx, fmt.Sprintf(`document.getElementById("view").contentDocument.getElementById(%q).textContent.includes(%q)`, id, needle))
}

func waitViewJS(t *testing.T, ctx context.Context, js string) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	var last string
	for {
		var ok bool
		err := chromedp.Run(ctx, chromedp.Evaluate("(() => { return ("+js+"); })()", &ok))
		if err == nil && ok {
			return
		}
		last = fmt.Sprint(err)
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for view (%s): %s\nhost log=%s", js, last, mustJSON(hostLog(t, ctx)))
		}
		time.Sleep(40 * time.Millisecond)
	}
}

func statsLayoutJS(desktop bool) string {
	if desktop {
		return `const doc = document.getElementById("view").contentDocument;
const tops = [...doc.querySelectorAll(".kpi")].map((el) => el.getBoundingClientRect().top);
if (tops.length !== 6) return "kpi count " + tops.length;
if (Math.max(...tops) - Math.min(...tops) > 2) return "kpi tops " + tops.join(",");
const labels = doc.querySelector(".day-labels");
if (!labels) return "missing day labels";
const size = parseFloat(getComputedStyle(labels).fontSize);
if (!(size >= 12)) return "day label font " + size;
const kpi = doc.getElementById("kpi-row").textContent;
const table = doc.getElementById("overview-quotas-table").textContent;
if (!kpi.includes("GiB") || !table.includes("GiB")) return "RAM units kpi=" + kpi + " table=" + table;
if (/\d(?:\.\d+)?\s+Mi\b/.test(table)) return "table still uses Mi";
return "";`
	}
	return `const doc = document.getElementById("view").contentDocument;
const tops = [...doc.querySelectorAll(".tab")].map((el) => el.getBoundingClientRect().top);
if (tops.length !== 6) return "tab count " + tops.length;
if (Math.max(...tops) - Math.min(...tops) > 2) return "tabs wrap " + tops.join(",");
const wrap = doc.getElementById("overview-quotas-table");
if (wrap.scrollWidth <= wrap.clientWidth + 8) return "quota table does not scroll " + wrap.scrollWidth + " vs " + wrap.clientWidth;
return "";`
}

func statsInitResult(version, theme string) map[string]any {
	return map[string]any{
		"protocolVersion": version,
		"hostInfo":        map[string]any{"name": "test-host", "version": "1"},
		"hostCapabilities": map[string]any{
			"serverTools": map[string]any{},
		},
		"hostContext": map[string]any{
			"theme":       theme,
			"displayMode": "inline",
			"platform":    "web",
			"locale":      "ru-RU",
			"containerDimensions": map[string]any{
				"maxWidth": 1400,
			},
			"styles": map[string]any{
				"variables": map[string]any{"--color-background-primary": "#080c14"},
			},
			"safeAreaInsets": map[string]any{"top": 0, "right": 0, "bottom": 0, "left": 0},
		},
	}
}

func statsBrowserSnapshot(user string) map[string]any {
	daily := make([]any, 0, 8)
	for i := 1; i <= 8; i++ {
		daily = append(daily, []any{fmt.Sprintf("2026-11-%02d", i), i})
	}
	return map[string]any{
		"meta": map[string]any{
			"uri":        statsAppURI,
			"user":       user,
			"admin":      false,
			"live":       true,
			"dataAsOf":   "тест",
			"filterTeam": "labs",
		},
		"tenants": []any{map[string]any{
			"name": "labs", "displayName": "Labs", "roles": "owner",
			"quota": map[string]any{
				"cpu_lim_u": 0.5, "cpu_lim_a": 2,
				"mem_lim_u": 512, "mem_lim_a": 1024,
				"pods_u": 3, "pods_a": 10, "svc_u": 1, "svc_a": 5,
			},
			"egress": map[string]any{"internet": false},
		}},
		"services": []any{},
		"incidents": map[string]any{
			"available": true,
			"active":    []any{},
			"resolvedSummary": map[string]any{
				"count": 8, "daily": daily,
				"by_severity": map[string]any{}, "by_type": map[string]any{},
				"by_source": map[string]any{}, "by_tenant": map[string]any{},
				"recent": []any{},
			},
		},
		"usage":      map[string]any{"available": false, "totals": map[string]any{}},
		"agents":     map[string]any{"available": false},
		"epics":      []any{},
		"readyItems": []any{},
		"platform": map[string]any{
			"operations": map[string]any{"count": 0, "by_risk": map[string]any{}, "by_scope": map[string]any{}},
			"commerce":   map[string]any{"available": false},
			"dataGaps":   []any{},
			"signups":    []any{},
		},
	}
}

func numField(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case json.Number:
		f, _ := n.Float64()
		return f
	default:
		return 0
	}
}

func mustJSON(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return err.Error()
	}
	return string(raw)
}
