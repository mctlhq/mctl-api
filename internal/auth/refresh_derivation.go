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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
)

// refreshTokenSuccessorDomain domain-separates rotation-successor derivation
// from every other use of JWTSecret in this service (JWT signing) and from
// mctl-telegram's own derivation, even though the two services can share the
// same underlying secret bytes in shared-hmac deployments.
const refreshTokenSuccessorDomain = "mctl-api-refresh-token-v1"

// deriveSuccessorRefreshToken deterministically computes the next refresh
// token in a rotation chain from its predecessor and the server's signing
// secret: same (secret, predecessor) always yields the same successor. This
// lets a client that never received a rotation response (e.g. a dropped
// connection) retry with the predecessor within the grace window and recover
// the exact successor a concurrent/earlier call already committed, instead of
// hard-failing. The server never persists the raw successor, only its
// SHA-256 hash, so this does not introduce recoverable token storage.
func deriveSuccessorRefreshToken(secret []byte, predecessor string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(refreshTokenSuccessorDomain))
	mac.Write([]byte{0})
	mac.Write([]byte(predecessor))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
