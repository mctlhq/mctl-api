// Copyright 2026 MCTL Authors
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

package session

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
)

const maxSessionFileBytes = 1 << 20

// ErrSessionFile is returned for any unusable session file. Its text never
// echoes file content.
var ErrSessionFile = errors.New("glovo session: unusable session file")

// ParseGlovoSessionFile extracts the credential pair from the JSON session
// file of the upstream login flow (denya/glovo-skill, src/auth/store.mjs).
// It decodes ONLY accessToken, refreshToken and the expiry fields; the
// customer's name, email, coordinates and device ids in the same file are
// never copied into the result. Expiry is the JWT exp claim, else
// createdAt (ms) plus expiresIn (s), as upstream's tokenStatus computes it.
func ParseGlovoSessionFile(r io.Reader, now time.Time) (Tokens, error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxSessionFileBytes+1))
	if err != nil || len(raw) > maxSessionFileBytes {
		return Tokens{}, ErrSessionFile
	}
	var f struct {
		AccessToken  string  `json:"accessToken"`
		RefreshToken string  `json:"refreshToken"`
		ExpiresIn    float64 `json:"expiresIn"`
		CreatedAt    float64 `json:"createdAt"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		return Tokens{}, ErrSessionFile
	}
	access := strings.TrimSpace(strings.TrimPrefix(f.AccessToken, "Bearer "))
	if access == "" || strings.TrimSpace(f.RefreshToken) == "" {
		return Tokens{}, ErrSessionFile
	}
	exp := jwtExp(access)
	if exp.IsZero() && f.CreatedAt > 0 && f.ExpiresIn > 0 {
		exp = time.UnixMilli(int64(f.CreatedAt)).Add(time.Duration(f.ExpiresIn * float64(time.Second)))
	}
	if exp.IsZero() {
		// Unknown expiry: treat as already expired so the first use refreshes.
		exp = now.Add(-time.Second)
	}
	return Tokens{Access: Secret(access), Refresh: Secret(strings.TrimSpace(f.RefreshToken)), AccessExpiresAt: exp.UTC()}, nil
}

func jwtExp(tok string) time.Time {
	parts := strings.Split(tok, ".")
	if len(parts) < 2 {
		return time.Time{}
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return time.Time{}
	}
	var c struct {
		Exp int64 `json:"exp"`
	}
	if json.Unmarshal(b, &c) != nil || c.Exp <= 0 {
		return time.Time{}
	}
	return time.Unix(c.Exp, 0)
}
