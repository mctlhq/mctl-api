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

package events

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestBuildEnvelope_Validation(t *testing.T) {
	ok := PullRequestFacts{Event: "pull_request", Action: "opened", DeliveryID: "abc-1",
		Repository: "mctlhq/mctl-api", Number: 1, HeadSHA: "not-a-sha"}
	env, err := BuildEnvelope(ok)
	if err != nil {
		t.Fatal(err)
	}
	if _, has := env.Subject["head_sha"]; has {
		t.Fatal("a malformed head sha must be dropped, not passed on")
	}
	for name, f := range map[string]PullRequestFacts{
		"action":   {Event: "pull_request", Action: "labeled", DeliveryID: "a", Repository: "o/r", Number: 1},
		"event":    {Event: "issues", Action: "opened", DeliveryID: "a", Repository: "o/r", Number: 1},
		"delivery": {Event: "pull_request", Action: "opened", DeliveryID: "a b", Repository: "o/r", Number: 1},
		"repo":     {Event: "pull_request", Action: "opened", DeliveryID: "a", Repository: "o/r/x", Number: 1},
		"number":   {Event: "pull_request", Action: "opened", DeliveryID: "a", Repository: "o/r", Number: 0},
	} {
		if _, err := BuildEnvelope(f); err == nil {
			t.Fatalf("%s: want an error", name)
		}
	}
}

// TestOutbox_Postgres runs against TEST_DATABASE_URL (set in CI).
func TestOutbox_Postgres(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping Postgres-backed event outbox test")
	}
	ctx := context.Background()
	o, err := NewOutbox(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	t.Cleanup(func() { _, _ = o.pool.Exec(ctx, "DELETE FROM event_outbox WHERE event_id LIKE 'github:pgtest-%'") })
	env, err := BuildEnvelope(PullRequestFacts{Event: "pull_request", Action: "opened",
		DeliveryID: "pgtest-1", Repository: "mctlhq/mctl-api", Number: 7})
	if err != nil {
		t.Fatal(err)
	}
	if ins, err := o.Enqueue(ctx, env, DefaultStream); err != nil || !ins {
		t.Fatalf("first enqueue: %v %v", ins, err)
	}
	if ins, err := o.Enqueue(ctx, env, DefaultStream); err != nil || ins {
		t.Fatalf("redelivery enqueue: inserted=%v err=%v, want false", ins, err)
	}
	rows, err := o.PendingOutbox(ctx, 1000)
	if err != nil {
		t.Fatal(err)
	}
	var mine *OutboxRow
	for i := range rows {
		if rows[i].EventID == env.ID {
			mine = &rows[i]
		}
	}
	if mine == nil {
		t.Fatalf("queued envelope not pending")
	}
	if err := o.MarkOutboxFailed(ctx, mine.ID, "boom"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := o.MarkOutboxPublished(ctx, mine.ID, now); err != nil {
		t.Fatal(err)
	}
	if n, err := o.PurgePublishedOutbox(ctx, now.Add(time.Minute)); err != nil || n < 1 {
		t.Fatalf("purge = %d, %v", n, err)
	}
}

// --- relay -------------------------------------------------------------------

type fakeStore struct {
	mu        sync.Mutex
	rows      []OutboxRow
	published map[int64]time.Time
	failures  map[int64]string
	markErr   error
}

func (f *fakeStore) PendingOutbox(_ context.Context, limit int) ([]OutboxRow, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []OutboxRow
	for _, r := range f.rows {
		if _, done := f.published[r.ID]; !done && len(out) < limit {
			out = append(out, r)
		}
	}
	return out, nil
}
func (f *fakeStore) MarkOutboxPublished(_ context.Context, id int64, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.markErr != nil {
		return f.markErr
	}
	f.published[id] = at
	return nil
}
func (f *fakeStore) MarkOutboxFailed(_ context.Context, id int64, reason string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failures[id] = reason
	return nil
}
func (f *fakeStore) PurgePublishedOutbox(context.Context, time.Time) (int64, error) { return 0, nil }
func (f *fakeStore) OutboxBacklog(context.Context) (int64, error)                   { return 0, nil }

type fakePub struct {
	mu      sync.Mutex
	calls   [][]string
	failOn  string
	failErr error
}

func (p *fakePub) XAdd(stream string, maxLen int, fields ...string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failOn != "" && stream == p.failOn {
		return "", p.failErr
	}
	p.calls = append(p.calls, append([]string{stream}, fields...))
	return "1-0", nil
}
func (p *fakePub) Close() {}

func newFakes(n int) (*fakeStore, *fakePub) {
	st := &fakeStore{published: map[int64]time.Time{}, failures: map[int64]string{}}
	for i := 1; i <= n; i++ {
		st.rows = append(st.rows, OutboxRow{ID: int64(i), EventID: fmt.Sprintf("github:delivery-%d", i),
			Stream: DefaultStream, Envelope: fmt.Sprintf(`{"n":%d}`, i), CreatedAt: time.Now()})
	}
	return st, &fakePub{}
}

func TestRelay_PublishesInOrderAndAudits(t *testing.T) {
	st, pub := newFakes(3)
	r := NewRelay(st, pub, false)
	if err := r.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	var events, audits []string
	for _, c := range pub.calls {
		switch c[0] {
		case DefaultStream:
			events = append(events, c[2])
		case AuditStream:
			audits = append(audits, strings.Join(c[1:], " "))
		}
	}
	if strings.Join(events, ",") != `{"n":1},{"n":2},{"n":3}` {
		t.Fatalf("published = %v", events)
	}
	if len(audits) != 3 || !strings.Contains(audits[0], "stage published") ||
		!strings.Contains(audits[0], "event_id github:delivery-1") {
		t.Fatalf("audit = %v", audits)
	}
	if len(st.published) != 3 || testutil.ToFloat64(r.published) != 3 {
		t.Fatalf("marked %d, counter %v", len(st.published), testutil.ToFloat64(r.published))
	}
}

func TestRelay_OutageStopsAtFirstFailureAndKeepsRows(t *testing.T) {
	st, pub := newFakes(3)
	pub.failOn, pub.failErr = DefaultStream, errors.New("connection refused")
	r := NewRelay(st, pub, false)
	if err := r.Drain(context.Background()); err == nil {
		t.Fatal("drain during an outage must report the failure")
	}
	if len(st.failures) != 1 || len(st.published) != 0 || testutil.ToFloat64(r.failures) != 1 {
		t.Fatalf("failures=%v published=%v", st.failures, st.published)
	}
	pub.failOn = ""
	if err := r.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(st.published) != 3 {
		t.Fatalf("after recovery published %d, want 3", len(st.published))
	}
}

func TestRelay_AuditFailureDoesNotBlockDelivery(t *testing.T) {
	st, pub := newFakes(2)
	pub.failOn, pub.failErr = AuditStream, &ServerError{Msg: "NOPERM"}
	r := NewRelay(st, pub, false)
	if err := r.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(st.published) != 2 {
		t.Fatalf("published %d, want 2", len(st.published))
	}
}

func TestRelay_UnmarkedPublishIsRetriedNotLost(t *testing.T) {
	st, pub := newFakes(1)
	st.markErr = errors.New("db gone")
	r := NewRelay(st, pub, false)
	if err := r.Drain(context.Background()); err == nil {
		t.Fatal("want the mark failure reported")
	}
	st.markErr = nil
	if err := r.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Published twice with the same envelope: the consumer deduplicates by id.
	n := 0
	for _, c := range pub.calls {
		if c[0] == DefaultStream {
			n++
		}
	}
	if n != 2 || len(st.published) != 1 {
		t.Fatalf("xadd=%d marked=%d, want 2 and 1", n, len(st.published))
	}
}

// --- RESP client against an in-process server ---------------------------------

func fakeValkey(t *testing.T, handle func(args []string) string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					var n int
					fmt.Sscanf(line, "*%d", &n)
					args := make([]string, n)
					for i := range args {
						_, _ = r.ReadString('\n')
						v, _ := r.ReadString('\n')
						args[i] = strings.TrimSuffix(v, "\r\n")
					}
					_, _ = c.Write([]byte(handle(args)))
				}
			}(conn)
		}
	}()
	return "redis://github-producer@" + ln.Addr().String() + "/0"
}

func TestClient_AuthThenXAdd(t *testing.T) {
	var mu sync.Mutex
	var seen [][]string
	url := fakeValkey(t, func(args []string) string {
		mu.Lock()
		seen = append(seen, args)
		mu.Unlock()
		switch args[0] {
		case "AUTH":
			if len(args) == 3 && args[1] == "github-producer" && args[2] == "pw" {
				return "+OK\r\n"
			}
			return "-WRONGPASS invalid\r\n"
		case "XADD":
			return "$15\r\n1789626542319-0\r\n"
		}
		return "-ERR unknown\r\n"
	})
	c, err := NewClient(url, "pw", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	id, err := c.XAdd(DefaultStream, 10000, "envelope", `{"a":1}`)
	if err != nil || id != "1789626542319-0" {
		t.Fatalf("xadd = %q, %v", id, err)
	}
	mu.Lock()
	defer mu.Unlock()
	want := "XADD mctl:events:github MAXLEN ~ 10000 * envelope {\"a\":1}"
	if len(seen) != 2 || strings.Join(seen[1], " ") != want {
		t.Fatalf("commands = %v", seen)
	}
}

func TestClient_ServerErrorIsTypedAndPasswordNeverInURL(t *testing.T) {
	url := fakeValkey(t, func(args []string) string {
		if args[0] == "AUTH" {
			return "+OK\r\n"
		}
		return "-NOPERM No permissions to access a key\r\n"
	})
	c, _ := NewClient(url, "pw", time.Second)
	defer c.Close()
	_, err := c.XAdd("mctl:events:telegram", 10, "envelope", "{}")
	var se *ServerError
	if !errors.As(err, &se) || !strings.HasPrefix(se.Msg, "NOPERM") {
		t.Fatalf("err = %v, want NOPERM ServerError", err)
	}
	if _, err := NewClient("redis://u:secret@127.0.0.1:6379/0", "", 0); err == nil {
		t.Fatal("a password embedded in the URL must be refused")
	}
}

// TestClient_RealValkey runs only against a real server (VALKEY_TEST_URL).
func TestClient_RealValkey(t *testing.T) {
	url := os.Getenv("VALKEY_TEST_URL")
	if url == "" {
		t.Skip("VALKEY_TEST_URL not set")
	}
	c, err := NewClient(url, os.Getenv("VALKEY_TEST_PASSWORD"), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.XAdd("mctl:events:github", 100, "envelope", `{"probe":true}`); err != nil {
		t.Fatal(err)
	}
}
