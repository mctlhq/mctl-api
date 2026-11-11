// Copyright 2026 MCTL Authors
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

package live_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/glovoprovider/live"
)

// No real Glovo call is ever made: every test talks to an httptest server on
// loopback and reads synthetic fixtures from testdata/.

const (
	testToken      = "tok-SYNTHETIC-aaaa"
	refreshedTok   = "tok-SYNTHETIC-bbbb"
	piiSentinel    = "PIISENTINEL"
	storeRefBurger = "700001:710001"
)

type recorded struct {
	Method string
	Path   string
	Query  string
	Header http.Header
	Body   []byte
}

type fakeGlovo struct {
	t      *testing.T
	srv    *httptest.Server
	mu     sync.Mutex
	reqs   []recorded
	routes map[string]http.HandlerFunc
}

func newFake(t *testing.T) *fakeGlovo {
	t.Helper()
	f := &fakeGlovo{t: t, routes: map[string]http.HandlerFunc{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.reqs = append(f.reqs, recorded{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Clone(), body})
		h := f.routes[r.Method+" "+r.URL.Path]
		f.mu.Unlock()
		if h == nil {
			http.NotFound(w, r)
			return
		}
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		h(w, r)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeGlovo) on(method, path string, h http.HandlerFunc) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes[method+" "+path] = h
}

func (f *fakeGlovo) onFixture(method, path, file string) {
	f.on(method, path, func(w http.ResponseWriter, _ *http.Request) { serveFixture(w, file) })
}

func (f *fakeGlovo) requests() []recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recorded(nil), f.reqs...)
}

func (f *fakeGlovo) count(method, path string) int {
	n := 0
	for _, r := range f.requests() {
		if r.Method == method && r.Path == path {
			n++
		}
	}
	return n
}

func (f *fakeGlovo) writes() int {
	n := 0
	for _, r := range f.requests() {
		if r.Method != http.MethodGet && !strings.Contains(r.Path, "/store_wall/") && !strings.HasSuffix(r.Path, "/view") {
			n++
		}
	}
	return n
}

func fixture(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name)) //nolint:gosec // fixed fixture dir
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func serveFixture(w http.ResponseWriter, name string) {
	b, err := os.ReadFile(filepath.Join("testdata", name)) //nolint:gosec // fixed fixture dir
	if err != nil {
		http.Error(w, "missing fixture", 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
}

type tokenSrc struct {
	mu        sync.Mutex
	token     string
	refreshed string
	tokenCalls,
	refreshCalls atomic.Int32
	refreshErr error
}

func newTokens() *tokenSrc { return &tokenSrc{token: testToken, refreshed: refreshedTok} }

func (s *tokenSrc) Token(context.Context) (string, error) {
	s.tokenCalls.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.token, nil
}

func (s *tokenSrc) Refresh(context.Context) (string, error) {
	s.refreshCalls.Add(1)
	if s.refreshErr != nil {
		return "", s.refreshErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.token = s.refreshed
	return s.token, nil
}

func baseCfg(url string) live.Config {
	return live.Config{
		BaseURL:        url,
		Currency:       "EUR",
		Delivery:       live.Delivery{CountryCode: "ZZ", CityCode: "SYNCITY", Latitude: "0.5", Longitude: "0.5"},
		ExtraHeaders:   map[string]string{"Glovo-Device-Urn": "glv:device:synthetic"},
		RequestTimeout: 2 * time.Second,
	}
}

func newReader(t *testing.T, f *fakeGlovo, ts live.TokenSource) *live.Reader {
	t.Helper()
	r, err := live.NewReader(baseCfg(f.srv.URL), ts)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func newWriter(t *testing.T, f *fakeGlovo, ts live.TokenSource) *live.Writer {
	t.Helper()
	w, err := live.NewWriter(baseCfg(f.srv.URL), ts)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func mustJSON(t testing.TB, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// --- stateful fake basket -------------------------------------------------

type fakeLine struct {
	BPID    string
	Product string
	Qty     int64
	Opts    [][2]string
	Unit    int64 // minor
}

type fakeBasket struct {
	mu        sync.Mutex
	exists    bool
	version   int
	lines     []fakeLine
	ignore    bool // accept writes but change nothing (reconcile mismatch)
	failWrite int  // HTTP status for writes, 0 = apply
	nextBP    int
}

func (b *fakeBasket) json() []byte {
	prods := []any{}
	for _, l := range b.lines {
		cz := []any{}
		for _, o := range l.Opts {
			cz = append(cz, map[string]any{"ids": map[string]any{"groupLegacyId": json.Number(o[0]), "legacyId": json.Number(o[1])}, "name": "n", "quantity": map[string]any{"increments": 1}})
		}
		total := l.Unit * l.Qty
		prods = append(prods, map[string]any{
			"ids":  map[string]any{"basketProductId": l.BPID, "id": json.Number(l.Product)},
			"name": "x", "quantity": map[string]any{"increments": l.Qty},
			"price":          map[string]any{"final": map[string]any{"major": json.Number(formatMinor(total))}},
			"customizations": cz,
		})
	}
	out, _ := json.Marshal(map[string]any{
		"basketId": "bsk-synth-1", "basketVersion": b.version, "storeId": 700001, "storeAddressId": 710001,
		"handlingStrategy": "DELIVERY", "products": prods,
	})
	return out
}

func formatMinor(m int64) string {
	major, minor := m/100, m%100
	return itoa(major) + "." + pad2(minor)
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }
func pad2(n int64) string {
	if n < 10 {
		return "0" + itoa(n)
	}
	return itoa(n)
}

const cid = "900001"

// wire registers the me, basket-by-store, view and write routes.
func (b *fakeBasket) wire(f *fakeGlovo) {
	f.onFixture("GET", "/v3/me", "me.json")
	f.onFixture("POST", "/v4/stores/700001/addresses/710001/products/800001/view", "product_view.json")
	base := "/v1/authenticated/customers/" + cid + "/baskets"
	f.on("GET", base+"/stores/700001", func(w http.ResponseWriter, _ *http.Request) {
		b.mu.Lock()
		defer b.mu.Unlock()
		if !b.exists {
			http.Error(w, `{"error":{"exceptionName":"NOT_FOUND"}}`, 404)
			return
		}
		_, _ = w.Write(b.json())
	})
	apply := func(w http.ResponseWriter, r *http.Request, fn func(body map[string]json.RawMessage) bool) {
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.failWrite != 0 {
			http.Error(w, "fail", b.failWrite)
			return
		}
		var body map[string]json.RawMessage
		_ = json.NewDecoder(r.Body).Decode(&body)
		if !b.ignore && !fn(body) {
			http.Error(w, "conflict", http.StatusConflict)
			return
		}
		if !b.ignore {
			b.version++
		}
		_, _ = w.Write([]byte(`{}`))
	}
	f.on("POST", base, func(w http.ResponseWriter, r *http.Request) {
		apply(w, r, func(body map[string]json.RawMessage) bool {
			b.exists = true
			b.lines = []fakeLine{b.lineFrom(body["products"], 0)}
			return true
		})
	})
	f.on("PUT", base+"/bsk-synth-1/products", func(w http.ResponseWriter, r *http.Request) {
		apply(w, r, func(body map[string]json.RawMessage) bool {
			if string(body["basketVersion"]) != itoa(int64(b.version)) {
				return false
			}
			var ps []json.RawMessage
			_ = json.Unmarshal(body["products"], &ps)
			b.lines = append(b.lines, b.lineFrom(mustRaw(ps[len(ps)-1:]), 0))
			return true
		})
	})
	f.on("PATCH", base+"/bsk-synth-1/products/quantity", func(w http.ResponseWriter, r *http.Request) {
		apply(w, r, func(body map[string]json.RawMessage) bool {
			if string(body["basketVersion"]) != itoa(int64(b.version)) {
				return false
			}
			var ps []struct {
				ID  string `json:"basketProductId"`
				Qty int64  `json:"quantity"`
			}
			_ = json.Unmarshal(body["products"], &ps)
			for i := range b.lines {
				if b.lines[i].BPID == ps[0].ID {
					b.lines[i].Qty = ps[0].Qty
				}
			}
			kept := b.lines[:0]
			for _, l := range b.lines {
				if l.Qty > 0 {
					kept = append(kept, l)
				}
			}
			b.lines = kept
			return true
		})
	})
}

func mustRaw(v any) json.RawMessage { b, _ := json.Marshal(v); return b }

func (b *fakeBasket) lineFrom(raw json.RawMessage, _ int) fakeLine {
	var ps []struct {
		IDs struct {
			ID json.Number `json:"id"`
		} `json:"ids"`
		Quantity struct {
			Increments int64 `json:"increments"`
		} `json:"quantity"`
		Customizations []struct {
			IDs struct {
				G json.Number `json:"groupLegacyId"`
				O json.Number `json:"legacyId"`
			} `json:"ids"`
		} `json:"customizations"`
	}
	_ = json.Unmarshal(raw, &ps)
	b.nextBP++
	l := fakeLine{BPID: "bp-new-" + itoa(int64(b.nextBP)), Product: ps[0].IDs.ID.String(), Qty: ps[0].Quantity.Increments, Unit: 950}
	for _, c := range ps[0].Customizations {
		l.Opts = append(l.Opts, [2]string{c.IDs.G.String(), c.IDs.O.String()})
	}
	return l
}

func seededBasket() *fakeBasket {
	return &fakeBasket{exists: true, version: 7, lines: []fakeLine{{BPID: "bp-synth-1", Product: "800001", Qty: 1, Unit: 1030, Opts: [][2]string{{"701", "801"}}}}}
}
