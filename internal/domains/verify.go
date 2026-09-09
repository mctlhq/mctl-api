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

package domains

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
)

// ChallengeLabel is the DNS label carrying the TXT ownership challenge, e.g.
// "_mctl-challenge.example.com".
const ChallengeLabel = "_mctl-challenge"

// verification methods reported in Result.Method.
const (
	MethodTXT   = "txt"
	MethodCNAME = "cname"
	MethodNone  = ""
)

// Resolver is the subset of *net.Resolver Verify needs, so tests can inject
// a stub instead of doing real DNS lookups.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
}

// Verifier proves domain ownership without requiring a CNAME answer, so
// Cloudflare-proxied hostnames (which only ever return edge A records) can
// still be verified: Cloudflare proxying rewrites the A/CNAME answer but
// never the TXT RRset.
type Verifier struct {
	resolver Resolver
}

// NewVerifier builds a Verifier that resolves against resolverAddr (host:port,
// e.g. "1.1.1.1:53"). An empty resolverAddr uses the system default resolver.
func NewVerifier(resolverAddr string) *Verifier {
	if resolverAddr == "" {
		return &Verifier{resolver: net.DefaultResolver}
	}
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, resolverAddr)
		},
	}
	return &Verifier{resolver: r}
}

// NewVerifierWithResolver builds a Verifier over an injected Resolver, for tests.
func NewVerifierWithResolver(r Resolver) *Verifier {
	return &Verifier{resolver: r}
}

// Result is the outcome of a single Verify call. A negative result is never
// an error — Verify only returns an error for a caller mistake (empty
// domain), never for "not configured yet".
type Result struct {
	Verified       bool   `json:"verified"`
	Method         string `json:"method,omitempty"`
	Reason         string `json:"reason,omitempty"`
	ExpectedRecord string `json:"expected_record"`
	ExpectedValue  string `json:"expected_value"`
}

// ChallengeValue returns the expected TXT record value for a verification token.
func ChallengeValue(token string) string {
	return "mctl-domain-verification=" + token
}

// ChallengeRecord returns the TXT record name that must be created for domain.
func ChallengeRecord(domain string) string {
	return ChallengeLabel + "." + domain
}

// Verify proves ownership of d.Domain. It first checks the TXT challenge
// record; if that is absent or does not match, it falls back to a CNAME
// check against cnameTarget (the unproxied fast path). A failed check
// returns Result{Verified:false, Reason:...}, not an error.
func (v *Verifier) Verify(ctx context.Context, d Domain, cnameTarget string) (Result, error) {
	if d.Domain == "" {
		return Result{}, errors.New("domains verify: empty domain")
	}

	record := ChallengeRecord(d.Domain)
	expectedValue := ChallengeValue(d.VerificationToken)
	result := Result{
		ExpectedRecord: record,
		ExpectedValue:  expectedValue,
	}

	txtValues, err := v.resolver.LookupTXT(ctx, record)
	if err == nil {
		for _, val := range txtValues {
			if strings.TrimSpace(val) == expectedValue {
				result.Verified = true
				result.Method = MethodTXT
				return result, nil
			}
		}
	}

	// Fast path: an unproxied CNAME pointing straight at the platform ingress
	// is accepted as proof of control without requiring the TXT record.
	// Compared case-insensitively: DNS names are case-insensitive by
	// definition (RFC 4343), and a resolver is free to echo back whatever
	// case the query used, or the case a zone operator happened to type into
	// a record — neither says anything about ownership, so a case mismatch
	// alone must never turn a legitimate CNAME into a failed verification.
	cname, err := v.resolver.LookupCNAME(ctx, d.Domain)
	if err == nil && strings.EqualFold(strings.TrimSuffix(cname, "."), strings.TrimSuffix(cnameTarget, ".")) {
		result.Verified = true
		result.Method = MethodCNAME
		return result, nil
	}

	result.Reason = fmt.Sprintf("no TXT record %s with value %q, and no CNAME to %s", record, expectedValue, cnameTarget)
	return result, nil
}
