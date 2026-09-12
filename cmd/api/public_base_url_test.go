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

package main

import (
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
)

// T7: the displayed URL is the OAuth issuer, not a second copy of config.
//
// Mutation check (verified by hand): changing publicBaseURL's body to
// `return cfg.SelfURL` unconditionally makes the first assertion below fail,
// since cfg.SelfURL and oauth.BaseURL are deliberately different values.
func TestPublicBaseURL(t *testing.T) {
	cfg := config{SelfURL: "https://config.example"}

	oauthWithBaseURL := &auth.OAuthServer{BaseURL: "https://issuer.example"}
	if got := publicBaseURL(cfg, oauthWithBaseURL); got != "https://issuer.example" {
		t.Errorf("publicBaseURL with OAuth enabled: got %q, want %q", got, "https://issuer.example")
	}

	if got := publicBaseURL(cfg, nil); got != "https://config.example" {
		t.Errorf("publicBaseURL with OAuth disabled (nil): got %q, want %q", got, "https://config.example")
	}

	oauthEmptyBaseURL := &auth.OAuthServer{BaseURL: ""}
	if got := publicBaseURL(cfg, oauthEmptyBaseURL); got != "https://config.example" {
		t.Errorf("publicBaseURL with OAuth server but empty BaseURL: got %q, want %q", got, "https://config.example")
	}
}
