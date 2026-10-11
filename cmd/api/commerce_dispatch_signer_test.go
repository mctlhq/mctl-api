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
	"bytes"
	"encoding/base64"
	"testing"
)

func TestCommerceDispatchSigner(t *testing.T) {
	seed := bytes.Repeat([]byte{0x07}, 32)
	if s, err := commerceDispatchSigner("", ""); s != nil || err != nil {
		t.Fatalf("unset: %v %v", s, err)
	}
	for _, half := range [][2]string{{"kid", ""}, {"", base64.StdEncoding.EncodeToString(seed)}} {
		if _, err := commerceDispatchSigner(half[0], half[1]); err == nil {
			t.Fatalf("one of two set must be an error: %q", half)
		}
	}
	var want []byte
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		s, err := commerceDispatchSigner(" kid-1 ", enc.EncodeToString(seed)+"\n")
		if err != nil || s == nil || s.KeyID() != "kid-1" {
			t.Fatalf("decode: %v %v", s, err)
		}
		if want == nil {
			want = s.PublicKey()
		} else if !bytes.Equal(want, s.PublicKey()) {
			t.Fatal("every alphabet must yield the same key")
		}
	}
	for _, bad := range []string{"not base64!", base64.StdEncoding.EncodeToString(seed[:16])} {
		if _, err := commerceDispatchSigner("kid", bad); err == nil {
			t.Fatalf("bad seed %q accepted", bad)
		}
	}
}
