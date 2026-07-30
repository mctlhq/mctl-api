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
	"net/http"
	"strings"
	"testing"
	"time"
)

// Credentials and clock from AWS's published Signature Version 4 examples
// for Amazon S3. These are documentation fixtures, not real secrets.
const (
	awsExampleAccessKey = "AKIAIOSFODNN7EXAMPLE"                   //nolint:gosec // published AWS doc fixture, not a real credential
	awsExampleSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" //nolint:gosec // published AWS doc fixture, not a real credential
	awsExampleHost      = "examplebucket.s3.amazonaws.com"
)

func awsExampleTime() time.Time {
	return time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)
}

// TestSignRequestAWSVectors checks the signer against AWS's own worked
// examples. Both fixtures sign exactly host;x-amz-content-sha256;x-amz-date,
// which is the header set this package signs.
func TestSignRequestAWSVectors(t *testing.T) {
	tests := []struct {
		name      string
		rawQuery  string
		path      string
		signature string
	}{
		{
			// "Example: GET Bucket Lifecycle" — exercises a valueless
			// query parameter, which must canonicalize to "lifecycle=".
			name:      "get bucket lifecycle",
			path:      "/",
			rawQuery:  "lifecycle",
			signature: "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543",
		},
		{
			// "Example: Get Bucket (List Objects)" — exercises multiple
			// query parameters and their canonical ordering.
			name:      "list objects",
			path:      "/",
			rawQuery:  "max-keys=2&prefix=J",
			signature: "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, "https://"+awsExampleHost+tc.path, nil)
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			req.URL.RawQuery = tc.rawQuery

			signRequest(req, awsExampleAccessKey, awsExampleSecretKey, "us-east-1", "s3", awsExampleTime())

			auth := req.Header.Get("Authorization")
			if !strings.Contains(auth, "Signature="+tc.signature) {
				t.Errorf("signature mismatch\n got: %s\nwant Signature=%s", auth, tc.signature)
			}
			if !strings.Contains(auth, "SignedHeaders=host;x-amz-content-sha256;x-amz-date") {
				t.Errorf("unexpected signed headers: %s", auth)
			}
			if !strings.Contains(auth, "Credential="+awsExampleAccessKey+"/20130524/us-east-1/s3/aws4_request") {
				t.Errorf("unexpected credential scope: %s", auth)
			}
		})
	}
}

// TestSignRequestLeavesRangeUnsigned pins the deliberate choice not to sign
// the Range header GetStep uses: signing it would make the signature
// depend on a header that transports may alter.
func TestSignRequestLeavesRangeUnsigned(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://"+awsExampleHost+"/test.txt", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Range", "bytes=-1024")

	signRequest(req, awsExampleAccessKey, awsExampleSecretKey, "auto", "s3", awsExampleTime())

	if strings.Contains(req.Header.Get("Authorization"), "range") {
		t.Errorf("Range must not be signed, got %s", req.Header.Get("Authorization"))
	}
}

func TestURIEncode(t *testing.T) {
	tests := []struct{ in, want string }{
		{"abc", "abc"},
		{"a b", "a%20b"},           // space must be %20, never "+"
		{"a~b-c_d.e", "a~b-c_d.e"}, // unreserved characters pass through
		{"a/b", "a%2Fb"},           // slash is encoded at segment level
		{"k=v&x", "k%3Dv%26x"},
		{"ü", "%C3%BC"},
	}
	for _, tc := range tests {
		if got := uriEncode(tc.in); got != tc.want {
			t.Errorf("uriEncode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCanonicalURIPreservesSeparators(t *testing.T) {
	path := "/argo-workflows-logs/wf-123/wf-123-run-poller-9/main.log"
	if got := canonicalURI(path); got != path {
		t.Errorf("canonicalURI(%q) = %q, want unchanged", path, got)
	}
	if got := canonicalURI(""); got != "/" {
		t.Errorf("canonicalURI(\"\") = %q, want /", got)
	}
}

// TestCanonicalQueryDoesNotDoubleEncode guards the split of duties between
// buildQuery (encodes once) and canonicalQuery (sorts only). Re-encoding
// here would corrupt every signature involving an escaped character.
func TestCanonicalQueryDoesNotDoubleEncode(t *testing.T) {
	raw := buildQuery(map[string]string{
		"list-type": "2",
		"prefix":    "wf name/",
	})
	if !strings.Contains(raw, "prefix=wf%20name%2F") {
		t.Fatalf("buildQuery did not encode as expected: %s", raw)
	}
	if got := canonicalQuery(raw); got != raw {
		t.Errorf("canonicalQuery re-encoded: got %q, want %q", got, raw)
	}
}

func TestBuildQuerySorts(t *testing.T) {
	got := buildQuery(map[string]string{
		"prefix":    "a",
		"list-type": "2",
	})
	if got != "list-type=2&prefix=a" {
		t.Errorf("buildQuery = %q, want sorted order", got)
	}
}

func TestCanonicalQueryAppendsEqualsForValuelessParam(t *testing.T) {
	if got := canonicalQuery("lifecycle"); got != "lifecycle=" {
		t.Errorf("canonicalQuery(lifecycle) = %q, want lifecycle=", got)
	}
}
