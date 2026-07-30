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

// Package argoarchive reads Argo Workflows step logs from the S3-compatible
// object store they are archived to (Cloudflare R2, bucket
// argo-workflows-logs).
//
// Why this exists: Loki only ingests long-lived service pods under the
// tenant naming convention, so mctl_get_service_logs structurally cannot
// reach an Argo step pod. The archive is also the more trustworthy source
// for post-mortems — Argo's wait sidecar uploads each step's log as part of
// the step itself, so it is complete by construction, whereas log shipping
// races podGC.
//
// Object layout written by Argo: <workflow-name>/<pod-name>/main.log
package argoarchive

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// r2Region is the fixed region string Cloudflare R2 expects in SigV4
// credentials scopes.
const r2Region = "auto"

// maxTailBytes bounds a single GetStep read. Agent step logs can reach
// megabytes; the tail is fetched with an HTTP Range request so memory use
// stays flat regardless of object size.
const (
	maxTailBytes     = 4 << 20  // 4 MiB
	minTailBytes     = 64 << 10 // 64 KiB
	bytesPerLineHint = 2048
)

// StepLog describes one archived step log object.
type StepLog struct {
	// Step is the pod name with the workflow-name prefix stripped, e.g.
	// "run-poller-1421612630" — this is what callers match on.
	Step string `json:"step"`
	// Pod is the full pod name.
	Pod string `json:"pod"`
	// Key is the full object key.
	Key string `json:"key"`
	// Size is the archived log size in bytes.
	Size int64 `json:"size"`
	// LastModified is the archive upload time.
	LastModified time.Time `json:"lastModified,omitempty"`
}

// Client reads archived workflow logs from an S3-compatible endpoint.
type Client struct {
	baseURL    string // scheme + host, no trailing slash
	bucket     string
	accessKey  string
	secretKey  string
	httpClient *http.Client
}

// NewClient creates a client for the given endpoint and bucket. endpoint
// may be given with or without a scheme (an R2 endpoint is usually
// configured bare, e.g. "<account>.r2.cloudflarestorage.com").
func NewClient(endpoint, bucket, accessKey, secretKey string) *Client {
	if !strings.Contains(endpoint, "://") {
		endpoint = "https://" + endpoint
	}
	return &Client{
		baseURL:    strings.TrimRight(endpoint, "/"),
		bucket:     bucket,
		accessKey:  accessKey,
		secretKey:  secretKey,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// listBucketResult is the ListObjectsV2 response shape.
type listBucketResult struct {
	XMLName               xml.Name `xml:"ListBucketResult"`
	IsTruncated           bool     `xml:"IsTruncated"`
	NextContinuationToken string   `xml:"NextContinuationToken"`
	Contents              []struct {
		Key          string    `xml:"Key"`
		Size         int64     `xml:"Size"`
		LastModified time.Time `xml:"LastModified"`
	} `xml:"Contents"`
}

// ListSteps returns every archived step log for a workflow, oldest first.
//
// An empty result is not an error: it means nothing was archived under
// that workflow name — either the name is wrong, the run predates the
// bucket's 30-day lifecycle window, or no step ever produced output.
//
// A step MISSING from an otherwise-populated list is itself a diagnosis:
// the step's pod never ran (e.g. stuck Pending), so there was no log to
// upload.
func (c *Client) ListSteps(ctx context.Context, workflow string) ([]StepLog, error) {
	if workflow == "" {
		return nil, fmt.Errorf("argoarchive: workflow name is required")
	}

	prefix := workflow + "/"
	var steps []StepLog
	continuation := ""

	// Bounded loop: a workflow has a handful of steps, so pagination is
	// defensive rather than expected. The cap stops a malformed or
	// looping continuation token from spinning forever.
	for page := 0; page < 20; page++ {
		params := map[string]string{
			"list-type": "2",
			"prefix":    prefix,
		}
		if continuation != "" {
			params["continuation-token"] = continuation
		}

		res, err := c.get(ctx, "/"+c.bucket, buildQuery(params), "")
		if err != nil {
			return nil, err
		}

		var result listBucketResult
		if err := xml.Unmarshal(res.body, &result); err != nil {
			return nil, fmt.Errorf("argoarchive: parse listing: %w", err)
		}

		for _, obj := range result.Contents {
			pod := podFromKey(obj.Key, prefix)
			if pod == "" {
				continue
			}
			steps = append(steps, StepLog{
				Step:         strings.TrimPrefix(pod, workflow+"-"),
				Pod:          pod,
				Key:          obj.Key,
				Size:         obj.Size,
				LastModified: obj.LastModified,
			})
		}

		if !result.IsTruncated || result.NextContinuationToken == "" {
			break
		}
		continuation = result.NextContinuationToken
	}

	return steps, nil
}

// mainLogName is the exact object name Argo's wait sidecar uploads a step's
// log as. Anything else under a pod's prefix (output artifacts, directory
// markers) is not a log and must not be surfaced as one.
const mainLogName = "main.log"

// podFromKey extracts the pod-name segment from "<prefix><pod>/main.log".
// Keys that do not have that exact shape are skipped by returning "".
func podFromKey(key, prefix string) string {
	rest := strings.TrimPrefix(key, prefix)
	if rest == key {
		return ""
	}
	pod, name, found := strings.Cut(rest, "/")
	if !found || pod == "" || name != mainLogName {
		return ""
	}
	return pod
}

// GetStep fetches the last tailLines lines of an archived step log.
//
// The tail is retrieved with a Range request so a multi-megabyte log does
// not have to be buffered in full. bytesPerLineHint is only a starting
// guess: if actual lines run longer (verbose agent output regularly
// exceeds 2KiB/line), the first window can come back short of tailLines
// lines. The window doubles until it holds enough lines, the whole object
// has been fetched, or maxTailBytes is reached.
func (c *Client) GetStep(ctx context.Context, key string, tailLines int) (string, error) {
	if key == "" {
		return "", fmt.Errorf("argoarchive: object key is required")
	}
	if tailLines <= 0 {
		tailLines = 100
	}

	want := int64(tailLines) * bytesPerLineHint
	if want < minTailBytes {
		want = minTailBytes
	}

	var text string
	for {
		if want > maxTailBytes {
			want = maxTailBytes
		}

		res, err := c.get(ctx, "/"+c.bucket+"/"+key, "", fmt.Sprintf("bytes=-%d", want))
		if err != nil {
			return "", err
		}

		text = string(res.body)
		wholeObject := !startsMidObject(res.contentRange)
		if !wholeObject {
			// The window opened mid-line, so drop the leading fragment
			// rather than hand back a truncated first line.
			if _, after, found := strings.Cut(text, "\n"); found {
				text = after
			}
		}

		if wholeObject || want >= maxTailBytes || countLines(text) >= tailLines {
			break
		}
		want *= 2
	}

	return lastLines(text, tailLines), nil
}

// countLines returns the number of newline-delimited lines in s.
func countLines(s string) int {
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return 0
	}
	return strings.Count(s, "\n") + 1
}

// startsMidObject reports whether a Content-Range response header
// describes a window that begins after the first byte.
//
// A suffix range larger than the object still comes back as 206 with
// "bytes 0-<n>/<n+1>" — the whole object — so status alone cannot decide
// this. Treating that case as partial silently ate the first line of every
// short log (caught against the live archive, where a 36-byte
// notify-telegram log lost its "telegram http=200" line).
func startsMidObject(contentRange string) bool {
	spec, ok := strings.CutPrefix(strings.TrimSpace(contentRange), "bytes ")
	if !ok {
		return false
	}
	start, _, ok := strings.Cut(spec, "-")
	if !ok {
		return false
	}
	start = strings.TrimSpace(start)
	// An unsatisfied or unknown range ("bytes */1234") is not a mid-object window.
	return start != "" && start != "0" && start != "*"
}

// lastLines returns at most n trailing lines of s.
func lastLines(s string, n int) string {
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return ""
	}
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// getResult is one signed GET response.
type getResult struct {
	body         []byte
	status       int
	contentRange string
}

// get issues a signed GET. rangeHeader may be empty. Any non-2xx response
// is returned as an error.
func (c *Client) get(ctx context.Context, path, rawQuery, rangeHeader string) (getResult, error) {
	u, err := url.Parse(c.baseURL)
	if err != nil {
		return getResult{}, fmt.Errorf("argoarchive: bad endpoint: %w", err)
	}
	u.Path = path
	// Pin the wire encoding to the encoding that gets signed. Without
	// this, Go's own path escaping could differ from canonicalURI's and
	// the signature would not match the request actually sent.
	u.RawPath = canonicalURI(path)
	u.RawQuery = rawQuery

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return getResult{}, fmt.Errorf("argoarchive: build request: %w", err)
	}
	if rangeHeader != "" {
		req.Header.Set("Range", rangeHeader)
	}

	signRequest(req, c.accessKey, c.secretKey, r2Region, "s3", time.Now())

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return getResult{}, fmt.Errorf("argoarchive: request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTailBytes+(1<<20)))
	if err != nil {
		return getResult{}, fmt.Errorf("argoarchive: read response: %w", err)
	}

	if resp.StatusCode == http.StatusRequestedRangeNotSatisfiable && rangeHeader != "" {
		// A suffix range against a zero-byte object (a step that produced
		// no output) is rejected with 416 rather than an empty 206 — this
		// is a valid empty log, not an error.
		return getResult{status: resp.StatusCode}, nil
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// Object-store errors are XML blobs; surface a trimmed form so a
		// misconfigured key or expired credential is obvious in the API
		// response instead of looking like "no logs archived".
		snippet := strings.TrimSpace(string(body))
		if len(snippet) > 300 {
			snippet = snippet[:300]
		}
		return getResult{}, fmt.Errorf("argoarchive: HTTP %d: %s", resp.StatusCode, snippet)
	}

	return getResult{
		body:         body,
		status:       resp.StatusCode,
		contentRange: resp.Header.Get("Content-Range"),
	}, nil
}
