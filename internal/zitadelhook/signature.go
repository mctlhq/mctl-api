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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"
)

// SignatureHeader is the header ZITADEL Actions v2 signs restCall payloads
// with (pkg/actions/signing.go in v4.19.2): "t=<unix>,v1=<hex hmac>[,v1=…]",
// where the HMAC-SHA256 covers "<unix>.<body>" under the target's signing key.
const SignatureHeader = "ZITADEL-Signature"

// SignatureTolerance is ZITADEL's own default tolerance.
const SignatureTolerance = 300 * time.Second

var (
	ErrNoSigningKey     = errors.New("no signing key configured")
	ErrSignatureMissing = errors.New("signature header missing")
	ErrSignatureHeader  = errors.New("signature header malformed")
	ErrSignatureAge     = errors.New("signature timestamp outside tolerance")
	ErrSignatureInvalid = errors.New("no valid signature")
)

// VerifySignature checks header against body for any of keys (a target's
// key can be rotated, so the previous one may be listed during the switch).
// Unlike ZITADEL's own helper it also refuses timestamps from the future.
func VerifySignature(body []byte, header string, keys []string, now time.Time) error {
	var usable []string
	for _, k := range keys {
		if k != "" {
			usable = append(usable, k)
		}
	}
	if len(usable) == 0 {
		return ErrNoSigningKey
	}
	if header == "" {
		return ErrSignatureMissing
	}
	var ts int64
	haveTS := false
	var sigs [][]byte
	for _, part := range strings.Split(header, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			return ErrSignatureHeader
		}
		switch k {
		case "t":
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil || haveTS {
				return ErrSignatureHeader
			}
			ts, haveTS = n, true
		case "v1":
			b, err := hex.DecodeString(v)
			if err == nil && len(b) == sha256.Size {
				sigs = append(sigs, b)
			}
		}
	}
	if !haveTS {
		return ErrSignatureHeader
	}
	if len(sigs) == 0 {
		return ErrSignatureInvalid
	}
	age := now.Sub(time.Unix(ts, 0))
	if age > SignatureTolerance || age < -SignatureTolerance {
		return ErrSignatureAge
	}
	prefix := strconv.FormatInt(ts, 10) + "."
	for _, key := range usable {
		mac := hmac.New(sha256.New, []byte(key))
		mac.Write([]byte(prefix))
		mac.Write(body)
		want := mac.Sum(nil)
		for _, s := range sigs {
			if hmac.Equal(want, s) {
				return nil
			}
		}
	}
	return ErrSignatureInvalid
}

// Sign builds a header the way ZITADEL does; used by tests and local tools.
func Sign(body []byte, key string, t time.Time) string {
	ts := strconv.FormatInt(t.Unix(), 10)
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(ts + "."))
	mac.Write(body)
	return "t=" + ts + ",v1=" + hex.EncodeToString(mac.Sum(nil))
}
