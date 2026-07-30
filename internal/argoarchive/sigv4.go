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

package argoarchive

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sort"
	"strings"
	"time"
)

// AWS Signature Version 4 for read-only S3 requests.
//
// Only the GET path is implemented: no payload signing beyond the
// empty-body hash, no chunked uploads, no presigning. That is the whole
// surface this package needs (ListObjectsV2 + GetObject), which is why a
// full S3 SDK — ~15-20 additional modules from a new vendor family in a
// service that also fronts OAuth, Vault and Kubernetes — is not pulled in
// for it. A signing mistake here fails loudly as an HTTP 403 from the
// object store; it cannot degrade into a silent security weakness.
//
// Reference: https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html

const (
	signAlgorithm = "AWS4-HMAC-SHA256"

	// emptyPayloadSHA256 is the hex SHA-256 of the empty string, used as
	// x-amz-content-sha256 for every bodyless request.
	emptyPayloadSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// signRequest attaches the Authorization, x-amz-date and
// x-amz-content-sha256 headers required for a SigV4-authenticated GET.
//
// signedTime is passed explicitly rather than read from the clock so tests
// can reproduce AWS's published test vectors exactly.
func signRequest(req *http.Request, accessKey, secretKey, region, service string, signedTime time.Time) {
	amzDate := signedTime.UTC().Format("20060102T150405Z")
	dateStamp := signedTime.UTC().Format("20060102")

	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", emptyPayloadSHA256)
	if req.Host != "" {
		req.Header.Set("Host", req.Host)
	} else {
		req.Header.Set("Host", req.URL.Host)
	}

	canonicalHeaders, signedHeaders := canonicalizeHeaders(req)

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI(req.URL.Path),
		canonicalQuery(req.URL.RawQuery),
		canonicalHeaders,
		signedHeaders,
		emptyPayloadSHA256,
	}, "\n")

	scope := strings.Join([]string{dateStamp, region, service, "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		signAlgorithm,
		amzDate,
		scope,
		hashHex([]byte(canonicalRequest)),
	}, "\n")

	signingKey := deriveSigningKey(secretKey, dateStamp, region, service)
	signature := hex.EncodeToString(hmacSHA256(signingKey, stringToSign))

	req.Header.Set("Authorization", signAlgorithm+
		" Credential="+accessKey+"/"+scope+
		", SignedHeaders="+signedHeaders+
		", Signature="+signature)
}

// canonicalizeHeaders returns the canonical header block and the
// semicolon-joined list of signed header names.
//
// Only host and the x-amz-* headers are signed. Everything else (notably
// Range, which GetStep uses to fetch a log tail) is deliberately left
// unsigned — AWS requires host and x-amz-* to be covered, and keeping the
// set minimal avoids signature breakage from headers added by transports
// or proxies after signing.
func canonicalizeHeaders(req *http.Request) (canonical, signed string) {
	names := make([]string, 0, len(req.Header)+1)
	values := make(map[string]string, len(req.Header)+1)

	for name, vals := range req.Header {
		lower := strings.ToLower(name)
		if lower != "host" && !strings.HasPrefix(lower, "x-amz-") {
			continue
		}
		names = append(names, lower)
		trimmed := make([]string, len(vals))
		for i, v := range vals {
			trimmed[i] = trimAndCollapse(v)
		}
		values[lower] = strings.Join(trimmed, ",")
	}
	sort.Strings(names)

	var b strings.Builder
	for _, name := range names {
		b.WriteString(name)
		b.WriteByte(':')
		b.WriteString(values[name])
		b.WriteByte('\n')
	}
	return b.String(), strings.Join(names, ";")
}

// trimAndCollapse strips surrounding whitespace and collapses internal
// runs of spaces, as required for canonical header values.
func trimAndCollapse(v string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(v)), " ")
}

// canonicalURI percent-encodes each path segment while preserving the
// separators. S3 object keys legitimately contain "/" (Argo stores logs at
// <workflow>/<pod>/main.log), so segments are encoded individually.
func canonicalURI(path string) string {
	if path == "" {
		return "/"
	}
	segments := strings.Split(path, "/")
	for i, seg := range segments {
		segments[i] = uriEncode(seg)
	}
	return strings.Join(segments, "/")
}

// canonicalQuery sorts an already-encoded query string.
//
// It deliberately does NOT re-encode: callers build the raw query with
// buildQuery, which applies uriEncode once. Encoding here as well would
// double-escape every "%" and produce a signature that does not match the
// bytes actually sent. Sorting is still applied so the canonical form is
// correct even if a caller appends parameters out of order.
func canonicalQuery(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	pairs := strings.Split(rawQuery, "&")
	kept := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		if pair == "" {
			continue
		}
		if !strings.Contains(pair, "=") {
			// SigV4 requires a trailing "=" for valueless parameters.
			pair += "="
		}
		kept = append(kept, pair)
	}
	sort.Strings(kept)
	return strings.Join(kept, "&")
}

// buildQuery renders parameters into a sorted, SigV4-canonical query
// string. The result is used verbatim as both the wire query and the
// signed query, so the two can never drift apart.
func buildQuery(params map[string]string) string {
	pairs := make([]string, 0, len(params))
	for k, v := range params {
		pairs = append(pairs, uriEncode(k)+"="+uriEncode(v))
	}
	sort.Strings(pairs)
	return strings.Join(pairs, "&")
}

// uriEncode percent-encodes per RFC 3986, leaving only the unreserved
// characters untouched. Go's url.QueryEscape cannot be used: it encodes
// space as "+" and escapes some characters AWS expects verbatim.
func uriEncode(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteString(strings.ToUpper(hex.EncodeToString([]byte{c})))
		}
	}
	return b.String()
}

func deriveSigningKey(secretKey, dateStamp, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secretKey), dateStamp)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	return hmacSHA256(kService, "aws4_request")
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func hashHex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
