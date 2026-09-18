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
	"unicode/utf8"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

const testSHA = "3e737a5d7c1f0f8f5c9a2b64a1e0d9c2b7f41a0e"

func TestBuildEnvelope_Validation(t *testing.T) {
	ok := PullRequestFacts{Event: "pull_request", Action: "opened", DeliveryID: "abc-1",
		Repository: "mctlhq/mctl-api", Number: 1, HeadSHA: testSHA}
	env, err := BuildEnvelope(ok)
	if err != nil {
		t.Fatal(err)
	}
	if env.Subject["head_sha"] != testSHA {
		t.Fatalf("head_sha = %q", env.Subject["head_sha"])
	}
	for name, f := range map[string]PullRequestFacts{
		"action":   {Event: "pull_request", Action: "labeled", DeliveryID: "a", Repository: "o/r", Number: 1},
		"event":    {Event: "issues", Action: "opened", DeliveryID: "a", Repository: "o/r", Number: 1},
		"delivery": {Event: "pull_request", Action: "opened", DeliveryID: "a b", Repository: "o/r", Number: 1},
		"repo":     {Event: "pull_request", Action: "opened", DeliveryID: "a", Repository: "o/r/x", Number: 1},
		"number":   {Event: "pull_request", Action: "opened", DeliveryID: "a", Repository: "o/r", Number: 0},
		"bad sha":  {Event: "pull_request", Action: "opened", DeliveryID: "a", Repository: "o/r", Number: 1, HeadSHA: "not-a-sha"},
		"no sha":   {Event: "pull_request", Action: "opened", DeliveryID: "a", Repository: "o/r", Number: 1},
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
	// One cleanup, delete then close: a deferred Close would run before any
	// t.Cleanup and leave rows behind that break the next run's first enqueue.
	t.Cleanup(func() {
		_, _ = o.pool.Exec(ctx, "DELETE FROM event_outbox WHERE event_id LIKE 'github:pgtest-%'")
		_, _ = o.pool.Exec(ctx, "DELETE FROM event_outbox_lease")
		o.Close()
	})
	_, _ = o.pool.Exec(ctx, "DELETE FROM event_outbox_lease")
	exerciseOutboxLease(ctx, t, o)
	env, err := BuildEnvelope(PullRequestFacts{Event: "pull_request", Action: "opened",
		DeliveryID: "pgtest-1", Repository: "mctlhq/mctl-api", Number: 7, HeadSHA: testSHA})
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
	// A relay that lost its lease mid-publish must not record a failure on a
	// row another replica already published.
	if err := o.MarkOutboxFailed(ctx, mine.ID, "stale relay"); err != nil {
		t.Fatal(err)
	}
	var attempts int
	var lastError string
	if err := o.pool.QueryRow(ctx, "SELECT attempts, COALESCE(last_error, '') FROM event_outbox WHERE id = $1", mine.ID).Scan(&attempts, &lastError); err != nil || lastError == "stale relay" {
		t.Fatalf("published row attempts=%d last_error=%q err=%v; a stale failure overwrote it", attempts, lastError, err)
	}
	if n, err := o.PurgePublishedOutbox(ctx, now.Add(time.Minute)); err != nil || n < 1 {
		t.Fatalf("purge = %d, %v", n, err)
	}
}

func exerciseOutboxLease(ctx context.Context, t *testing.T, s *Outbox) {
	t.Helper()
	now := time.Now()
	acquire := func(holder string, at time.Time) bool {
		t.Helper()
		ok, err := s.AcquireOutboxLease(ctx, holder, at, time.Minute)
		if err != nil {
			t.Fatalf("acquire %s: %v", holder, err)
		}
		return ok
	}
	if !acquire("a", now) {
		t.Fatal("a could not take a free lease")
	}
	if acquire("b", now.Add(30*time.Second)) {
		t.Fatal("b took a lease a still holds")
	}
	if !acquire("a", now.Add(30*time.Second)) {
		t.Fatal("a could not renew its own lease")
	}
	if acquire("b", now.Add(80*time.Second)) {
		t.Fatal("b took the lease before a's renewal expired")
	}
	if !acquire("b", now.Add(2*time.Minute)) {
		t.Fatal("b could not take an expired lease")
	}
	if err := s.ReleaseOutboxLease(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if acquire("a", now.Add(2*time.Minute)) {
		t.Fatal("a released a lease it no longer held")
	}
	if err := s.ReleaseOutboxLease(ctx, "b"); err != nil {
		t.Fatal(err)
	}
	if !acquire("a", now.Add(2*time.Minute)) {
		t.Fatal("a could not take a released lease")
	}
}

// --- relay -------------------------------------------------------------------

type fakeStore struct {
	mu        sync.Mutex
	rows      []OutboxRow
	published map[int64]time.Time
	failures  map[int64]string
	markErr   error

	leaseHolder  string
	leaseUntil   time.Time
	acquires     int
	blockPending bool // PendingOutbox waits for its context, like a stalled pool

	releaseBounded, releaseLive bool

	pendingErr  error // returned by PendingOutbox alongside whatever rows it found
	purges      int
	backlogCall int
}

func (f *fakeStore) PendingOutbox(ctx context.Context, limit int) ([]OutboxRow, error) {
	if f.blockPending {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []OutboxRow
	for _, r := range f.rows {
		if _, done := f.published[r.ID]; !done && len(out) < limit {
			out = append(out, r)
		}
	}
	return out, f.pendingErr
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
func (f *fakeStore) AcquireOutboxLease(_ context.Context, holder string, now time.Time, ttl time.Duration) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.acquires++
	if f.leaseHolder != "" && f.leaseHolder != holder && now.Before(f.leaseUntil) {
		return false, nil
	}
	f.leaseHolder, f.leaseUntil = holder, now.Add(ttl)
	return true, nil
}
func (f *fakeStore) ReleaseOutboxLease(ctx context.Context, holder string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, f.releaseBounded = ctx.Deadline()
	f.releaseLive = ctx.Err() == nil
	if f.leaseHolder == holder {
		f.leaseHolder = ""
	}
	return nil
}
func (f *fakeStore) PurgePublishedOutbox(context.Context, time.Time) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.purges++
	return 0, nil
}
func (f *fakeStore) OutboxBacklog(context.Context) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.backlogCall++
	return int64(len(f.rows) - len(f.published)), nil
}
func (f *fakeStore) counts() (purges, backlog int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.purges, f.backlogCall
}

type fakePub struct {
	mu       sync.Mutex
	calls    [][]string
	failOn   string
	failErr  error
	attempts int
	delay    time.Duration
	closes   int
	onXAdd   func(stream string) // runs before the append is recorded
}

func (p *fakePub) XAdd(_ context.Context, stream string, maxLen int, fields ...string) (string, error) {
	p.mu.Lock()
	p.attempts++
	delay := p.delay
	p.mu.Unlock()
	time.Sleep(delay)
	if p.onXAdd != nil {
		p.onXAdd(stream)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failOn != "" && stream == p.failOn {
		return "", p.failErr
	}
	p.calls = append(p.calls, append([]string{stream}, fields...))
	return "1-0", nil
}
func (p *fakePub) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closes++
}
func (p *fakePub) closed() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closes
}
func (p *fakePub) tries() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.attempts
}

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
	// The first, unmarked XADD still counts as an attempt.
	if _, ok := st.failures[1]; !ok {
		t.Fatal("the published-but-unmarked attempt was not recorded")
	}
}

func TestRelay_LeaseReleaseOutlivesShutdownButIsBounded(t *testing.T) {
	st, pub := newFakes(1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // shutdown already under way
	_ = NewRelay(st, pub, false).Drain(ctx)
	if !st.releaseLive {
		t.Fatal("lease release ran with the cancelled shutdown context and could not hand over")
	}
	if !st.releaseBounded {
		t.Fatal("lease release has no deadline; an unreachable database would block shutdown")
	}
}

func TestRelay_LostLeaseStopsPublishingMidBatch(t *testing.T) {
	st, pub := newFakes(5)
	r := NewRelay(st, pub, false)
	clock := time.Now()
	r.now = func() time.Time { return clock }
	appended := 0
	pub.onXAdd = func(stream string) {
		if stream == AuditStream {
			return
		}
		appended++
		// Each publish is slow; after the second, this replica's lease has
		// expired and another replica takes it.
		clock = clock.Add(leaseTTL / 2)
		if appended == 2 {
			st.mu.Lock()
			st.leaseHolder, st.leaseUntil = "other-replica", clock.Add(time.Hour)
			st.mu.Unlock()
		}
	}
	if err := r.Drain(context.Background()); !errors.Is(err, ErrLeaseHeld) {
		t.Fatalf("drain = %v, want ErrLeaseHeld once ownership is lost", err)
	}
	if appended != 2 {
		t.Fatalf("published %d rows, want 2: nothing after the lease was lost", appended)
	}
}

func TestRelay_PublishIsAuditedEvenWhenTheMarkFails(t *testing.T) {
	st, pub := newFakes(1)
	st.markErr = errors.New("db down")
	r := NewRelay(st, pub, false)
	_ = r.Drain(context.Background())
	audited := 0
	for _, c := range pub.calls {
		if c[0] == AuditStream {
			audited++
		}
	}
	if audited != 1 {
		t.Fatalf("audit entries = %d, want 1 for the append that happened", audited)
	}
}

func TestRelay_LeaseHeldElsewherePublishesNothing(t *testing.T) {
	st, pub := newFakes(2)
	st.leaseHolder, st.leaseUntil = "other-replica", time.Now().Add(time.Minute)
	r := NewRelay(st, pub, false)
	if err := r.Drain(context.Background()); !errors.Is(err, ErrLeaseHeld) {
		t.Fatalf("drain = %v, want ErrLeaseHeld", err)
	}
	if len(pub.calls) != 0 || st.leaseHolder != "other-replica" {
		t.Fatalf("published %d entries, lease=%q; want nothing and the lease untouched", len(pub.calls), st.leaseHolder)
	}
}

func TestRelay_TwoReplicasPublishEachRowOnce(t *testing.T) {
	st, pub := newFakes(20)
	pub.delay = time.Millisecond
	a, b := NewRelay(st, pub, false), NewRelay(st, pub, false)
	var wg sync.WaitGroup
	for _, r := range []*Relay{a, b} {
		wg.Add(1)
		go func(r *Relay) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				if err := r.Drain(context.Background()); err == nil {
					st.mu.Lock()
					done := len(st.published) == 20
					st.mu.Unlock()
					if done {
						return
					}
				}
				time.Sleep(time.Millisecond)
			}
		}(r)
	}
	wg.Wait()
	seen := map[string]int{}
	for _, c := range pub.calls {
		if c[0] == DefaultStream {
			seen[c[2]]++
		}
	}
	if len(seen) != 20 {
		t.Fatalf("published %d distinct rows, want 20", len(seen))
	}
	for env, n := range seen {
		if n != 1 {
			t.Fatalf("%s published %d times across replicas", env, n)
		}
	}
}

func TestRelay_NotifyDoesNotCutBackoffShort(t *testing.T) {
	st, pub := newFakes(1)
	pub.failOn, pub.failErr = DefaultStream, errors.New("valkey down")
	r := NewRelay(st, pub, false)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	// The first drain fails at once and arms a 1s backoff; a burst of new
	// ingests inside that second must not trigger more attempts.
	end := time.Now().Add(700 * time.Millisecond)
	for time.Now().Before(end) {
		r.Notify()
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	pub.mu.Lock()
	defer pub.mu.Unlock()
	if pub.attempts != 1 {
		t.Fatalf("xadd attempts during backoff = %d, want 1", pub.attempts)
	}
}

func TestRelay_FailingAuditDoesNotHoldDeliveryBack(t *testing.T) {
	st, pub := newFakes(5)
	pub.failOn, pub.failErr = AuditStream, errors.New("audit stream unavailable")
	r := NewRelay(st, pub, false)
	if err := r.Drain(context.Background()); err != nil {
		t.Fatalf("drain = %v, want nil: audit is best effort", err)
	}
	if len(st.published) != 5 {
		t.Fatalf("published %d rows, want 5", len(st.published))
	}
	// One audit attempt, then the pass stops paying for a failing trail.
	if pub.attempts != 6 {
		t.Fatalf("xadd attempts = %d, want 5 events + 1 audit", pub.attempts)
	}
}

func TestRelay_NotifyDoesNotRetryAHeldLeaseEarly(t *testing.T) {
	st, pub := newFakes(1)
	st.leaseHolder, st.leaseUntil = "other-replica", time.Now().Add(time.Hour)
	r := NewRelay(st, pub, false)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	// Another replica owns the outbox: new ingests inside the 1s lease retry
	// must not make this replica contend for the lease again.
	end := time.Now().Add(700 * time.Millisecond)
	for time.Now().Before(end) {
		r.Notify()
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.acquires != 1 {
		t.Fatalf("lease acquire attempts while held elsewhere = %d, want 1", st.acquires)
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
				defer func() { _ = c.Close() }()
				r := bufio.NewReader(c)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					var n int
					if _, err := fmt.Sscanf(line, "*%d", &n); err != nil {
						return
					}
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

func TestClient_TimeoutBoundsReconnectAndCommandTogether(t *testing.T) {
	url := fakeValkey(t, func(args []string) string {
		// Each step alone fits the timeout; together they do not.
		time.Sleep(300 * time.Millisecond)
		if args[0] == "AUTH" || args[0] == "SELECT" {
			return "+OK\r\n"
		}
		return "$3\r\n1-0\r\n"
	})
	c, err := NewClient(url, "pw", 500*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	start := time.Now()
	if _, err := c.XAdd(context.Background(), DefaultStream, 10, "envelope", "{}"); err == nil {
		t.Fatal("xadd succeeded after exceeding the client timeout")
	}
	if took := time.Since(start); took > 800*time.Millisecond {
		t.Fatalf("call took %v, want it bounded by the 500ms timeout", took)
	}
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
	id, err := c.XAdd(context.Background(), DefaultStream, 10000, "envelope", `{"a":1}`)
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
	_, err := c.XAdd(context.Background(), "mctl:events:telegram", 10, "envelope", "{}")
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
	if _, err := c.XAdd(context.Background(), "mctl:events:github", 100, "envelope", `{"probe":true}`); err != nil {
		t.Fatal(err)
	}
}

func TestClient_UserWithoutPasswordIsRejected(t *testing.T) {
	if _, err := NewClient("redis://github-producer@127.0.0.1:6379/0", "", time.Second); err == nil {
		t.Fatal("a named ACL user without a password was accepted")
	}
}

func TestClient_NegativeDatabaseIsRejected(t *testing.T) {
	if _, err := NewClient("redis://valkey.platform-events.svc:6379/-1", "", time.Second); err == nil {
		t.Fatal("a negative database index was accepted")
	}
}

func TestClient_URLWithoutUserinfo(t *testing.T) {
	c, err := NewClient("redis://valkey.platform-events.svc:6379/0", "", time.Second)
	if err != nil || c.username != "" {
		t.Fatalf("client = %+v, err = %v; want no username and no panic", c, err)
	}
}

func TestClient_CancelledContextStopsABlockedCall(t *testing.T) {
	url := fakeValkey(t, func(args []string) string {
		if args[0] == "AUTH" {
			return "+OK\r\n"
		}
		time.Sleep(3 * time.Second) // never answers in time
		return "+OK\r\n"
	})
	c, _ := NewClient(url, "pw", 10*time.Second)
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	start := time.Now()
	if _, err := c.XAdd(ctx, DefaultStream, 10, "envelope", "{}"); err == nil {
		t.Fatal("want an error from the cancelled call")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("cancelled call took %v; the context must unblock it", elapsed)
	}
}

func TestTruncateUTF8_NeverSplitsARune(t *testing.T) {
	s := strings.Repeat("a", 499) + "ж" // the 2-byte rune straddles byte 500
	got := truncateUTF8(s, 500)
	if !utf8.ValidString(got) || len(got) > 500 {
		t.Fatalf("truncated to %d bytes, valid=%v", len(got), utf8.ValidString(got))
	}
}

func TestRelay_RunPublishesOnNotifyAndStopsOnCancel(t *testing.T) {
	st, pub := newFakes(0)
	r := NewRelay(st, pub, false)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()

	st.mu.Lock()
	st.rows = append(st.rows, OutboxRow{ID: 1, EventID: "github:late", Stream: DefaultStream, Envelope: "{}", CreatedAt: time.Now()})
	st.mu.Unlock()
	r.Notify()
	deadline := time.Now().Add(5 * time.Second)
	for {
		st.mu.Lock()
		_, ok := st.published[1]
		st.mu.Unlock()
		if ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Notify did not publish the new row")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

func TestRelay_StalledDatabaseFailsThePassInsteadOfHanging(t *testing.T) {
	st, pub := newFakes(1)
	st.blockPending = true
	r := NewRelay(st, pub, false)
	r.storeTimeout = 50 * time.Millisecond
	done := make(chan error, 1)
	go func() { done <- r.Drain(context.Background()) }()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("drain = %v, want a deadline error", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a stalled database query held the drain")
	}
}

func TestClient_OversizedBulkReplyIsRejected(t *testing.T) {
	url := fakeValkey(t, func(args []string) string {
		if args[0] == "XADD" {
			return "$9223372036854775807\r\n"
		}
		return "+OK\r\n"
	})
	c, err := NewClient(url, "pw", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.XAdd(context.Background(), "s", 10, "k", "v"); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("xadd = %v, want an oversized-reply error", err)
	}
}

// addRow appends a pending row while the relay is running.
func (f *fakeStore) addRow(id int64, envelope string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rows = append(f.rows, OutboxRow{ID: id, EventID: fmt.Sprintf("github:delivery-%d", id),
		Stream: DefaultStream, Envelope: envelope, CreatedAt: time.Now()})
}

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, within time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", within, what)
}

// A failed scan must not hand the relay the rows the iteration did reach:
// publishing those would skip the ones it never got to, and the stream is
// ordered by outbox id.
func TestRelay_DrainPublishesNothingWhenPendingFails(t *testing.T) {
	st, pub := newFakes(3)
	st.pendingErr = errors.New("connection reset by peer")
	r := NewRelay(st, pub, false)
	err := r.Drain(context.Background())
	if err == nil || !strings.Contains(err.Error(), "connection reset") {
		t.Fatalf("Drain err = %v, want the store error", err)
	}
	if n := pub.tries(); n != 0 {
		t.Fatalf("XAdd attempts = %d, want 0: a partial batch was published", n)
	}
}

// Run drains on Notify rather than waiting out the 30s safety timer, and
// releases the publisher when its context is cancelled.
func TestRelay_RunDrainsOnNotifyAndClosesOnCancel(t *testing.T) {
	st, pub := newFakes(1)
	r := NewRelay(st, pub, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // a t.Fatalf below must not leave Run alive for the next test
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()

	waitFor(t, 2*time.Second, "the first drain", func() bool { return pub.tries() > 0 })
	first := pub.tries()

	st.addRow(2, `{"n":2}`)
	r.Notify()
	// safetyInterval is 30s, so anything this quick can only be the wakeup.
	waitFor(t, 2*time.Second, "the notify-driven drain", func() bool { return pub.tries() > first })

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after its context was cancelled")
	}
	if n := pub.closed(); n != 1 {
		t.Fatalf("publisher Close calls = %d, want 1", n)
	}
}

// After a publish failure Run holds its backoff: a burst of new rows must not
// hammer a Valkey that is already down. The first pass also refreshes the
// backlog gauge and runs the retention purge.
func TestRelay_RunHoldsBackoffAndKeepsHousekeeping(t *testing.T) {
	st, pub := newFakes(1)
	pub.failOn, pub.failErr = DefaultStream, errors.New("valkey down")
	r := NewRelay(st, pub, false)
	frozen := time.Date(2026, 9, 18, 6, 0, 0, 0, time.UTC)
	r.now = func() time.Time { return frozen } // retryAt stays ahead of now

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()

	waitFor(t, 2*time.Second, "the failing drain", func() bool { return pub.tries() > 0 })
	waitFor(t, 2*time.Second, "housekeeping", func() bool {
		purges, backlog := st.counts()
		return purges > 0 && backlog > 0
	})
	after := pub.tries()

	for i := 0; i < 20; i++ {
		st.addRow(int64(100+i), `{"n":0}`)
		r.Notify()
	}
	// The backoff is 1s; nothing may be retried inside it.
	time.Sleep(300 * time.Millisecond)
	if n := pub.tries(); n != after {
		t.Fatalf("XAdd attempts = %d, want %d: Notify cut the backoff short", n, after)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after its context was cancelled")
	}
}
