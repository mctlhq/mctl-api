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
	"net"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/mctlhq/mctl-api/internal/audit"
)

const maxUserAgentLen = 512

type clientMetaKey struct{}

// ClientMeta is the request identity recorded on audit events.
type ClientMeta struct {
	IP        string
	UserAgent string
	RequestID string
}

// ParseTrustedProxyCIDRs parses a comma-separated list of CIDRs or bare IPs
// (bare IPv4 becomes /32, IPv6 /128). Empty input yields a nil list, which
// means X-Forwarded-For is never trusted.
func ParseTrustedProxyCIDRs(raw string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.Contains(part, "/") {
			ip := net.ParseIP(part)
			if ip == nil {
				return nil, fmt.Errorf("trusted proxy CIDR %q: not an IP or CIDR", part)
			}
			if ip.To4() != nil {
				part += "/32"
			} else {
				part += "/128"
			}
		}
		_, n, err := net.ParseCIDR(part)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}

func clientMetaMiddleware(trusted []*net.IPNet) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			meta := ClientMeta{
				IP:        clientIP(r, trusted),
				UserAgent: truncateUA(r.UserAgent()),
				RequestID: middleware.GetReqID(r.Context()),
			}
			ctx := context.WithValue(r.Context(), clientMetaKey{}, meta)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ClientMetaFromContext returns the meta captured before chi RealIP rewrites
// RemoteAddr from untrusted X-Forwarded-For headers.
func ClientMetaFromContext(ctx context.Context) (ClientMeta, bool) {
	m, ok := ctx.Value(clientMetaKey{}).(ClientMeta)
	return m, ok
}

func clientIP(r *http.Request, trusted []*net.IPNet) string {
	host := remoteHost(r.RemoteAddr)
	ip := net.ParseIP(host)
	if ip != nil && isTrustedProxy(ip, trusted) {
		if xff := firstForwardedIP(r.Header.Get("X-Forwarded-For")); xff != "" {
			return xff
		}
	}
	if ip != nil {
		return ip.String()
	}
	return host
}

func remoteHost(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

func firstForwardedIP(xff string) string {
	if xff == "" {
		return ""
	}
	first := strings.TrimSpace(strings.Split(xff, ",")[0])
	ip := net.ParseIP(first)
	if ip == nil {
		return ""
	}
	return ip.String()
}

func isTrustedProxy(ip net.IP, trusted []*net.IPNet) bool {
	for _, n := range trusted {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func truncateUA(ua string) string {
	ua = strings.TrimSpace(ua)
	if len(ua) <= maxUserAgentLen {
		return ua
	}
	return ua[:maxUserAgentLen]
}

func (h *Handlers) logAudit(r *http.Request, entry audit.Entry) {
	if h.opts.AuditLog == nil {
		return
	}
	if r != nil {
		if m, ok := ClientMetaFromContext(r.Context()); ok {
			entry.ClientIP = m.IP
			entry.UserAgent = m.UserAgent
			entry.RequestID = m.RequestID
		}
	}
	h.opts.AuditLog.Log(entry)
}
