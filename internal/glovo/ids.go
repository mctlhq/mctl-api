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

package glovo

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"
)

// ID prefixes minted by the store. Callers never choose an id.
const (
	prefixInstall    = "gin_"
	prefixConnection = "gcn_"
	prefixAudit      = "gae_"
	prefixSecretRef  = "gsr_"
)

// newPrefixedID mints prefix + a 26 character ULID. It is a copy of the
// commerce.newULID minting, kept local so this package does not depend on
// commerce.
func newPrefixedID(prefix string, t time.Time) (string, error) {
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	var raw [16]byte
	binary.BigEndian.PutUint64(raw[0:8], uint64(t.UnixMilli())<<16) //nolint:gosec // UnixMilli is positive for every date this runs on
	if _, err := rand.Read(raw[6:]); err != nil {
		return "", fmt.Errorf("glovo: crypto/rand: %w", err)
	}
	var out [26]byte
	var acc uint64
	bits := 0
	pos := 25
	for i := 15; i >= 0; i-- {
		acc |= uint64(raw[i]) << bits
		bits += 8
		for bits >= 5 && pos >= 0 {
			out[pos] = alphabet[acc&31]
			acc >>= 5
			bits -= 5
			pos--
		}
	}
	for pos >= 0 {
		out[pos] = alphabet[acc&31]
		acc >>= 5
		pos--
	}
	return prefix + string(out[:]), nil
}
