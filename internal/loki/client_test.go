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

package loki

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// queryFuncs run the same request through both public entry points, so every
// behaviour below is checked for QueryRange and QueryNamespace.
var queryFuncs = map[string]func(c *Client) ([]LogLine, error){
	"QueryRange": func(c *Client) ([]LogLine, error) {
		return c.QueryRange(context.Background(), "team", "app", 10, time.Hour)
	},
	"QueryNamespace": func(c *Client) ([]LogLine, error) {
		return c.QueryNamespace(context.Background(), "team", 10, time.Hour)
	},
}

// countingBody is a response body that counts the bytes handed to its reader
// and records Close. It serves total bytes of data (then EOF) so that a read
// that is not bounded finishes, and fails the test on the count instead of
// hanging. If failAfter is non-nil it returns that error once failAt bytes
// have been served.
type countingBody struct {
	total  int
	fill   byte
	failAt int
	fail   error

	read   int
	closed bool
}

func (b *countingBody) Read(p []byte) (int, error) {
	if b.fail != nil && b.read >= b.failAt {
		return 0, b.fail
	}
	remaining := b.total - b.read
	if b.fail != nil && b.failAt-b.read < remaining {
		remaining = b.failAt - b.read
	}
	if remaining <= 0 {
		return 0, io.EOF
	}
	if len(p) > remaining {
		p = p[:remaining]
	}
	for i := range p {
		p[i] = b.fill
	}
	b.read += len(p)
	return len(p), nil
}

func (b *countingBody) Close() error {
	b.closed = true
	return nil
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// clientWithBody returns a Client whose transport answers every request with
// the given status and body, and no network involved.
func clientWithBody(status int, body io.ReadCloser) *Client {
	return &Client{
		baseURL: "http://loki.invalid",
		httpClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: status, Body: body, Header: http.Header{}, Request: r}, nil
		})},
	}
}

func serverReplying(t *testing.T, status int, body string) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return NewClient(srv.URL)
}

func TestNon200_ErrorBodyBoundsAndMarker(t *testing.T) {
	long := strings.Repeat("x", 513)
	huge := strings.Repeat("y", 1<<20)
	// 511 ASCII bytes then a two-byte rune: the 512-byte cut falls inside it.
	splitRune := strings.Repeat("a", 511) + "é" + "tail"

	cases := []struct {
		name          string
		body          string
		wantBody      string // exactly the body text expected after "HTTP 502: "
		wantTruncated bool
	}{
		{"short", "upstream boom", "upstream boom", false},
		{"empty", "", "", false},
		{"exactly 512 bytes", strings.Repeat("e", 512), strings.Repeat("e", 512), false},
		{"513 bytes", long, strings.Repeat("x", 512), true},
		{"1 MiB", huge, strings.Repeat("y", 512), true},
		{"cut inside a multi-byte rune", splitRune, strings.Repeat("a", 511), true},
	}
	for fn, call := range queryFuncs {
		for _, tc := range cases {
			t.Run(fn+"/"+tc.name, func(t *testing.T) {
				_, err := call(serverReplying(t, http.StatusBadGateway, tc.body))
				if err == nil {
					t.Fatal("a 502 must be an error")
				}
				want := "loki: HTTP 502: " + tc.wantBody
				if tc.wantTruncated {
					want += truncatedMarker
				}
				if err.Error() != want {
					t.Fatalf("error = %q (len %d), want %q", clip(err.Error()), len(err.Error()), clip(want))
				}
				if got := strings.Contains(err.Error(), truncatedMarker); got != tc.wantTruncated {
					t.Errorf("truncation marker present = %v, want %v", got, tc.wantTruncated)
				}
				if !utf8.ValidString(err.Error()) {
					t.Error("the error must stay valid UTF-8")
				}
			})
		}
	}
}

func clip(s string) string {
	if len(s) > 80 {
		return s[:80] + fmt.Sprintf("...(%d bytes)", len(s))
	}
	return s
}

// The bound is on bytes READ from the upstream, not only on the length of the
// message built from them.
func TestNon200_ReadsAtMost513BytesAndCloses(t *testing.T) {
	for fn, call := range queryFuncs {
		t.Run(fn, func(t *testing.T) {
			body := &countingBody{total: 1 << 20, fill: 'z'}
			_, err := call(clientWithBody(http.StatusInternalServerError, body))
			if err == nil {
				t.Fatal("a 500 must be an error")
			}
			if body.read > maxErrorBody+1 {
				t.Fatalf("read %d bytes of an error body, want at most %d", body.read, maxErrorBody+1)
			}
			if body.read < maxErrorBody+1 {
				t.Fatalf("read %d bytes, need %d to tell a truncated body from an exact one", body.read, maxErrorBody+1)
			}
			if !body.closed {
				t.Error("the response body must be closed")
			}
			if !strings.HasSuffix(err.Error(), truncatedMarker) {
				t.Errorf("error %q lacks the truncation marker", clip(err.Error()))
			}
		})
	}
}

func TestNon200_ShortBodyIsReadWholeAndClosed(t *testing.T) {
	for fn, call := range queryFuncs {
		t.Run(fn, func(t *testing.T) {
			body := &countingBody{total: 100, fill: 'q'}
			_, err := call(clientWithBody(http.StatusServiceUnavailable, body))
			if err == nil || err.Error() != "loki: HTTP 503: "+strings.Repeat("q", 100) {
				t.Fatalf("error = %v", err)
			}
			if body.read != 100 || !body.closed {
				t.Errorf("read %d (want 100), closed %v", body.read, body.closed)
			}
		})
	}
}

// A body that fails while the error is being read is reported with the status
// and the cause intact.
func TestNon200_ReadFailureWrapsCauseAndCloses(t *testing.T) {
	boom := errors.New("connection reset by peer")
	for fn, call := range queryFuncs {
		t.Run(fn, func(t *testing.T) {
			body := &countingBody{total: 1000, fill: 'r', failAt: 40, fail: boom}
			_, err := call(clientWithBody(http.StatusInternalServerError, body))
			if !errors.Is(err, boom) {
				t.Fatalf("error %v does not wrap the read failure", err)
			}
			if !strings.Contains(err.Error(), "HTTP 500") {
				t.Errorf("error %q lost the status", err)
			}
			if !body.closed {
				t.Error("the response body must be closed after a failed read")
			}
		})
	}
}

// The bound applies to error bodies only: a valid success response far larger
// than 512 bytes is parsed whole.
func TestSuccessBodyLargerThanErrorBoundIsNotTruncated(t *testing.T) {
	const n = 40
	var values []string
	for i := 0; i < n; i++ {
		values = append(values, fmt.Sprintf(`["%d","line %02d %s"]`, 1700000000000000000+int64(i), i, strings.Repeat("p", 40)))
	}
	payload := `{"status":"success","data":{"resultType":"streams","result":[{"stream":{"app":"demo"},"values":[` +
		strings.Join(values, ",") + `]}]}}`
	if len(payload) <= 4*maxErrorBody {
		t.Fatalf("fixture is only %d bytes; it must be well above the %d-byte error bound", len(payload), maxErrorBody)
	}

	for fn, call := range queryFuncs {
		t.Run(fn, func(t *testing.T) {
			c := serverReplying(t, http.StatusOK, payload)
			lines, err := call(c)
			if err != nil {
				t.Fatalf("a valid success response must parse, got %v", err)
			}
			if len(lines) != n {
				t.Fatalf("got %d lines, want %d: the success body was cut", len(lines), n)
			}
			// Most recent first.
			if !strings.HasPrefix(lines[0].Line, fmt.Sprintf("line %02d", n-1)) || lines[0].Labels["app"] != "demo" {
				t.Errorf("unexpected first line %+v", lines[0])
			}
		})
	}
}

func TestSuccessBodyReadFailureIsReported(t *testing.T) {
	boom := errors.New("stream aborted")
	body := &countingBody{total: 5000, fill: '{', failAt: 700, fail: boom}
	_, err := queryFuncs["QueryRange"](clientWithBody(http.StatusOK, body))
	if !errors.Is(err, boom) || !strings.Contains(err.Error(), "read response") {
		t.Fatalf("error = %v, want the read failure wrapped as a response read error", err)
	}
	if !body.closed {
		t.Error("the response body must be closed")
	}
}
