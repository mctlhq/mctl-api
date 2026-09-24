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

package principals

import (
	"crypto/rand"
	"fmt"
	"time"
)

// crockford is the ULID alphabet: Crockford base32, no I, L, O or U.
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// newULID returns a 26-character ULID: 48 bits of millisecond time, then 80
// random bits. Lexicographic order follows creation time, which keeps the
// ids of rows created together close in an index.
func newULID(now time.Time) (string, error) {
	var b [16]byte
	ms := uint64(now.UnixMilli())
	for i := 5; i >= 0; i-- {
		b[i] = byte(ms)
		ms >>= 8
	}
	if _, err := rand.Read(b[6:]); err != nil {
		return "", fmt.Errorf("principals: random: %w", err)
	}
	// 128 bits → 26 base32 digits, the first carrying only 3 bits.
	var out [26]byte
	hi := uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
	lo := uint64(b[8])<<56 | uint64(b[9])<<48 | uint64(b[10])<<40 | uint64(b[11])<<32 |
		uint64(b[12])<<24 | uint64(b[13])<<16 | uint64(b[14])<<8 | uint64(b[15])
	for i := 25; i >= 0; i-- {
		out[i] = crockford[lo&31]
		lo = lo>>5 | hi<<59
		hi >>= 5
	}
	return string(out[:]), nil
}

// PrincipalIDPrefix marks a canonical principal id (mctl-api#373 D1).
const PrincipalIDPrefix = "prn_"

// externalIdentityIDPrefix marks an external identity row.
const externalIdentityIDPrefix = "xid_"

func newPrefixedID(prefix string, now time.Time) (string, error) {
	u, err := newULID(now)
	if err != nil {
		return "", err
	}
	return prefix + u, nil
}
