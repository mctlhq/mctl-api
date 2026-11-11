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

package auth

import (
	"errors"
	"testing"
	"time"
)

func TestValidateGlovoResource(t *testing.T) {
	o := newResourceServer(t)
	for _, tc := range []struct {
		name string
		res  string
		ok   bool
	}{
		{"empty", "", true},
		{"intended", GlovoResourceIntended, true},
		{"http", "http://glovo.mctl.ai/mcp", false},
		{"relative", "glovo", false},
		{"fragment", GlovoResourceIntended + "#x", false},
		{"base", o.BaseURL, false},
		{"base mcp", o.BaseURL + "/mcp", false},
		{"support", testSupportRes, false},
		{"support slash", testSupportRes + "/", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o.GlovoResource = tc.res
			if err := o.ValidateGlovoResource(); (err == nil) != tc.ok {
				t.Fatalf("err = %v, ok want %v", err, tc.ok)
			}
		})
	}
	o.GlovoResource = testSupportRes
	if err := o.ValidateSupportResource(); err == nil {
		t.Fatal("support resource equal to glovo accepted")
	}
}

func TestGlovoResourceNotMinted(t *testing.T) {
	o := newResourceServer(t)
	if _, err := o.ResolveResource([]string{GlovoResourceIntended}); !errors.Is(err, ErrInvalidTarget) || errors.Is(err, ErrGlovoNotReady) {
		t.Fatalf("unset: %v", err)
	}
	o.GlovoResource = GlovoResourceIntended
	if _, err := o.FlowResource([]string{GlovoResourceIntended}); !errors.Is(err, ErrGlovoNotReady) || !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("set: %v", err)
	}
	if _, err := o.ResolveResource([]string{GlovoResourceIntended, GlovoResourceIntended}); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("repeated: %v", err)
	}
	if got, err := o.ResolveResource([]string{testSupportRes}); err != nil || got != testSupportRes {
		t.Fatalf("support: %q %v", got, err)
	}
}

func TestGlovoExactAudience(t *testing.T) {
	o := newResourceServer(t)
	mint := func(aud audience) string {
		tok, err := signJWT(jwtPayload{Issuer: o.BaseURL, Subject: "alice", Audience: aud,
			ExpiresAt: time.Now().Add(time.Hour).Unix()}, o.JWTSecret)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	// Unconfigured: refused.
	if _, err := o.ValidateJWT(mint(audience{GlovoResourceIntended})); err == nil {
		t.Fatal("glovo aud accepted while unconfigured")
	}
	o.GlovoResource = GlovoResourceIntended
	u, err := o.ValidateJWT(mint(audience{GlovoResourceIntended}))
	if err != nil || !u.IsGlovoAudience() || u.IsSupportAudience() {
		t.Fatalf("single glovo aud: %v", err)
	}
	for _, aud := range []audience{
		{GlovoResourceIntended, o.BaseURL},
		{GlovoResourceIntended, testSupportRes},
		{GlovoResourceIntended, GlovoResourceIntended},
		{"https://other.example"},
	} {
		if _, err := o.ValidateJWT(mint(aud)); err == nil {
			t.Fatalf("aud %v accepted", aud)
		}
	}
	api, err := o.ValidateJWT(mint(audience{o.BaseURL}))
	if err != nil || api.IsGlovoAudience() {
		t.Fatalf("api token: %v", err)
	}
	if _, err := o.IssueSupportToken(u, time.Minute); !errors.Is(err, ErrSupportTokenRefused) {
		t.Fatalf("support mint for glovo caller: %v", err)
	}
	if u.IsGlovoWorker() || (&User{ID: GlovoWorkerUserID}).IsGlovoWorker() {
		t.Fatal("glovo worker must never be reported")
	}
}
