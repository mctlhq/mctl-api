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
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/mctlhq/mctl-api/internal/audit"
)

func TestParseTrustedProxyCIDRs(t *testing.T) {
	nets, err := ParseTrustedProxyCIDRs("10.42.4.181, 10.42.5.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if len(nets) != 2 {
		t.Fatalf("len=%d", len(nets))
	}
	if !nets[0].Contains(mustIP("10.42.4.181")) || nets[0].Contains(mustIP("10.42.4.182")) {
		t.Fatalf("bare IP should be /32: %s", nets[0])
	}
	if !nets[1].Contains(mustIP("10.42.5.93")) {
		t.Fatalf("cidr should contain 10.42.5.93")
	}
}

func TestClientIP_IgnoresSpoofedXFF(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	req.RemoteAddr = "10.0.0.9:1234"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := clientIP(req, nil); got != "10.0.0.9" {
		t.Fatalf("untrusted XFF leaked: got %q", got)
	}
}

func TestClientIP_TrustsXFFFromTraefik(t *testing.T) {
	trusted, err := ParseTrustedProxyCIDRs("10.42.4.181/32,10.42.6.242/32")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	req.RemoteAddr = "10.42.4.181:443"
	req.Header.Set("X-Forwarded-For", "6.6.6.6, 203.0.113.9")
	if got := clientIP(req, trusted); got != "203.0.113.9" {
		t.Fatalf("got %q, want client 203.0.113.9 (rightmost, ignoring spoofed leftmost)", got)
	}
}

func TestClientIP_RejectsGarbageXFF(t *testing.T) {
	trusted, err := ParseTrustedProxyCIDRs("10.42.4.181/32")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.42.4.181:443"
	req.Header.Set("X-Forwarded-For", "not-an-ip")
	if got := clientIP(req, trusted); got != "10.42.4.181" {
		t.Fatalf("got %q, want RemoteAddr", got)
	}
}

func TestLogAudit_RecordsIPAndUA(t *testing.T) {
	logger := audit.NewLogger()
	trusted, err := ParseTrustedProxyCIDRs("10.42.4.181/32")
	if err != nil {
		t.Fatal(err)
	}
	h := &Handlers{opts: Options{AuditLog: logger, TrustedProxyCIDRs: trusted}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/operations/x/execute", nil)
	req.RemoteAddr = "10.42.4.181:443"
	req.Header.Set("X-Forwarded-For", "198.51.100.20")
	req.Header.Set("User-Agent", "soc-test/1.0")
	clientMetaMiddleware(trusted)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.logAudit(r, audit.Entry{UserID: "alice", Operation: "deploy-service", Status: "submitted"})
	})).ServeHTTP(httptest.NewRecorder(), req)

	entries := logger.List(1)
	if len(entries) != 1 {
		t.Fatalf("entries=%d", len(entries))
	}
	if entries[0].ClientIP != "198.51.100.20" {
		t.Fatalf("ClientIP=%q", entries[0].ClientIP)
	}
	if entries[0].UserAgent != "soc-test/1.0" {
		t.Fatalf("UserAgent=%q", entries[0].UserAgent)
	}
}

func TestTruncateUA(t *testing.T) {
	long := strings.Repeat("a", maxUserAgentLen+20)
	if got := truncateUA(long); len(got) != maxUserAgentLen {
		t.Fatalf("len=%d", len(got))
	}
	// Multi-byte tail must not be split mid-rune.
	mb := strings.Repeat("a", maxUserAgentLen-1) + "é"
	got := truncateUA(mb)
	if !utf8.ValidString(got) {
		t.Fatalf("truncated UA is invalid UTF-8: %q", got)
	}
}

func mustIP(s string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil {
		panic("invalid IP " + s)
	}
	return ip
}
