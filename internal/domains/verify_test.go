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
	"testing"
)

// stubResolver is an in-memory Resolver double so tests need no real DNS.
type stubResolver struct {
	txt   map[string][]string
	cname map[string]string
}

func (r *stubResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if v, ok := r.txt[name]; ok {
		return v, nil
	}
	return nil, errors.New("no such TXT record")
}

func (r *stubResolver) LookupCNAME(_ context.Context, host string) (string, error) {
	if v, ok := r.cname[host]; ok {
		return v, nil
	}
	return "", errors.New("no such CNAME record")
}

const cnameTarget = "labs-genai-leader.mctl.ai"

func TestVerify_TXTMatch(t *testing.T) {
	d := Domain{Domain: "genai-leader.example.com", VerificationToken: "abc123"}
	resolver := &stubResolver{
		txt: map[string][]string{
			ChallengeRecord(d.Domain): {ChallengeValue(d.VerificationToken)},
		},
	}
	v := NewVerifierWithResolver(resolver)

	result, err := v.Verify(context.Background(), d, cnameTarget)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !result.Verified || result.Method != MethodTXT {
		t.Fatalf("expected TXT verification success, got %+v", result)
	}
}

func TestVerify_TXTPresentWrongToken(t *testing.T) {
	d := Domain{Domain: "genai-leader.example.com", VerificationToken: "abc123"}
	resolver := &stubResolver{
		txt: map[string][]string{
			ChallengeRecord(d.Domain): {"mctl-domain-verification=wrong-token"},
		},
	}
	v := NewVerifierWithResolver(resolver)

	result, err := v.Verify(context.Background(), d, cnameTarget)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Verified {
		t.Fatalf("expected verification failure for mismatched token, got %+v", result)
	}
	if result.ExpectedRecord == "" || result.ExpectedValue == "" {
		t.Fatalf("expected the negative result to still carry the expected record/value, got %+v", result)
	}
}

func TestVerify_CNAMEFastPath(t *testing.T) {
	d := Domain{Domain: "genai-leader.example.com", VerificationToken: "abc123"}
	resolver := &stubResolver{
		cname: map[string]string{
			d.Domain: cnameTarget,
		},
	}
	v := NewVerifierWithResolver(resolver)

	result, err := v.Verify(context.Background(), d, cnameTarget)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !result.Verified || result.Method != MethodCNAME {
		t.Fatalf("expected CNAME fast-path success, got %+v", result)
	}
}

// TestVerify_CloudflareProxiedWithTXT is the regression the issue reports:
// a Cloudflare-proxied domain never answers with a CNAME (only edge A
// records), but the TXT challenge is untouched by proxying and must still
// verify.
func TestVerify_CloudflareProxiedWithTXT(t *testing.T) {
	d := Domain{Domain: "genai-leader.example.com", VerificationToken: "abc123"}
	resolver := &stubResolver{
		txt: map[string][]string{
			ChallengeRecord(d.Domain): {ChallengeValue(d.VerificationToken)},
		},
		// No CNAME entry at all — Cloudflare-shaped answer.
	}
	v := NewVerifierWithResolver(resolver)

	result, err := v.Verify(context.Background(), d, cnameTarget)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !result.Verified || result.Method != MethodTXT {
		t.Fatalf("expected TXT verification to succeed without any CNAME, got %+v", result)
	}
}

func TestVerify_NeitherTXTNorCNAME(t *testing.T) {
	d := Domain{Domain: "genai-leader.example.com", VerificationToken: "abc123"}
	v := NewVerifierWithResolver(&stubResolver{})

	result, err := v.Verify(context.Background(), d, cnameTarget)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Verified {
		t.Fatalf("expected verification failure with no records at all, got %+v", result)
	}
	if result.Reason == "" {
		t.Fatalf("expected a reason to be set on failure")
	}
}
