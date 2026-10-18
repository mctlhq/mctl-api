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

package zitadelhook

import (
	"errors"
	"testing"
	"time"
)

func TestVerifySignature(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	body := []byte(`{"a":1}`)
	good := Sign(body, "key", now)

	if err := VerifySignature(body, good, []string{"key"}, now); err != nil {
		t.Fatalf("valid: %v", err)
	}
	if err := VerifySignature(body, good, []string{"old", "key"}, now); err != nil {
		t.Fatalf("second key: %v", err)
	}
	// ZITADEL may send several v1= values (one per key); one match suffices.
	if err := VerifySignature(body, good+",v1="+Sign(body, "other", now)[len("t=1800000000,v1="):], []string{"key"}, now); err != nil {
		t.Fatalf("extra signature: %v", err)
	}

	cases := map[string]struct {
		body   []byte
		header string
		keys   []string
		now    time.Time
		want   error
	}{
		"no keys":         {body, good, nil, now, ErrNoSigningKey},
		"empty key":       {body, good, []string{""}, now, ErrNoSigningKey},
		"no header":       {body, "", []string{"key"}, now, ErrSignatureMissing},
		"wrong key":       {body, good, []string{"nope"}, now, ErrSignatureInvalid},
		"tampered body":   {[]byte(`{"a":2}`), good, []string{"key"}, now, ErrSignatureInvalid},
		"too old":         {body, good, []string{"key"}, now.Add(301 * time.Second), ErrSignatureAge},
		"from the future": {body, good, []string{"key"}, now.Add(-301 * time.Second), ErrSignatureAge},
		"no timestamp":    {body, "v1=00", []string{"key"}, now, ErrSignatureHeader},
		"two timestamps":  {body, "t=1,t=2,v1=00", []string{"key"}, now, ErrSignatureHeader},
		"garbage":         {body, "nonsense", []string{"key"}, now, ErrSignatureHeader},
		"no v1":           {body, "t=1800000000", []string{"key"}, now, ErrSignatureInvalid},
		"retimed": {body, "t=1800000001" + good[len("t=1800000000"):], []string{"key"}, now,
			ErrSignatureInvalid},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if err := VerifySignature(c.body, c.header, c.keys, c.now); !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
	if err := VerifySignature(body, good, []string{"key"}, now.Add(299*time.Second)); err != nil {
		t.Fatalf("inside tolerance: %v", err)
	}
}
