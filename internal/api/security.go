// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package api

import "net/http"

// securityHeaders sets baseline browser isolation headers on every response.
// HSTS is only set when the request arrived over TLS (directly or via a
// trusted ingress that sets X-Forwarded-Proto), so local HTTP dev is unaffected.
func securityHeaders() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "no-referrer")
			h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
			h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
			h.Set("X-Permitted-Cross-Domain-Policies", "none")
			if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
				h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			}
			next.ServeHTTP(w, r)
		})
	}
}

// clusterOnly serves next only for in-cluster callers. Ingress (Traefik) always
// sets X-Forwarded-For and/or X-Forwarded-Proto; kube probes and vmagent scrapes
// hit the Service directly and do not. Unauthenticated internet scrapes of
// /metrics are therefore 404 rather than a public telemetry dump.
func clusterOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			http.NotFound(w, r)
			return
		}
		if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}
