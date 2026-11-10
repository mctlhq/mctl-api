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

package glovojoin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/httprate"

	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/connect"
	"github.com/mctlhq/mctl-api/internal/glovojoin/contract"
)

// bodyMax bounds a join request body; the largest is a preview or prepare
// request of two short strings.
const bodyMax = 4096

var (
	idempotencyKeyRE = regexp.MustCompile(`^[\x21-\x7e]{1,128}$`)
)

// JoinConnector is the #961 connect surface of the join routes.
type JoinConnector interface {
	Connect(ctx context.Context, sc connect.JoinScope, idempotencyKey string) (*connect.ConnectOutcome, error)
	Current(ctx context.Context, sc connect.JoinScope) (*glovo.Connection, error)
}

var _ JoinConnector = (*connect.Service)(nil)

// Refused is one refusal for the audit and metrics hooks. Reason is the
// internal reason of design 4.2; it never reaches the wire.
type Refused struct {
	Route  string
	Code   glovo.Code
	Wire   string
	Status int
	Reason string
}

// Routes is the nine join routes of design 3. A nil dependency makes the
// routes that need it answer 503 not_ready, never a partial answer.
type Routes struct {
	Verifier  *SubjectVerifier
	Refs      *ScopeRefs
	Reader    *Reader
	Prepare   *Preparer
	Status    *StatusReader
	Connect   JoinConnector
	Readiness Readiness
	// OnRefused is called once per refusal; it must not log request bodies.
	OnRefused func(Refused)
	// Limits override the contract defaults (60, 10 and 600 per minute); zero
	// keeps the contract value.
	PerSubject, Writes, Aggregate int

	once                       sync.Once
	doc                        *contract.Document
	perSubject, writes, aggreg *httprate.RateLimiter
}

func (rt *Routes) init() {
	rt.once.Do(func() {
		rt.doc = contract.MustLoad()
		pick := func(v, def int) int {
			if v > 0 {
				return v
			}
			return def
		}
		h := httprate.WithResponseHeaders(httprate.ResponseHeaders{RetryAfter: "Retry-After"})
		rt.perSubject = httprate.NewRateLimiter(pick(rt.PerSubject, rt.doc.Limits.PerSubjectPerMinute), time.Minute, h)
		rt.writes = httprate.NewRateLimiter(pick(rt.Writes, rt.doc.Limits.WritesPerSubjectPerMinute), time.Minute, h)
		rt.aggreg = httprate.NewRateLimiter(pick(rt.Aggregate, rt.doc.Limits.FacadeAggregatePerMinute), time.Minute, h)
	})
}

// Handler returns the router of the nine routes, relative to
// contract.BasePath.
func (rt *Routes) Handler() http.Handler {
	rt.init()
	r := chi.NewRouter()
	for i := range rt.doc.Routes {
		route := rt.doc.Routes[i]
		h := rt.handlerFor(route.ID)
		if h == nil {
			panic("glovojoin: no handler for route " + route.ID)
		}
		r.Method(route.Method, route.Path, rt.pipeline(route, h))
	}
	return r
}

// RouteTable is the (method, path, id) of every mounted route, for the
// route-table assertion of T11.
func (rt *Routes) RouteTable() []contract.Route {
	rt.init()
	return append([]contract.Route(nil), rt.doc.Routes...)
}

type joinHandler func(w http.ResponseWriter, r *http.Request, sub Subject, route contract.Route) (status int, body []byte, replayed bool, rf *Refusal)

func (rt *Routes) handlerFor(id string) joinHandler {
	switch id {
	case "resolve":
		return rt.resolve
	case "connection":
		return rt.connection
	case "connect":
		return rt.connect
	case "orders":
		return rt.orders
	case "preview":
		return rt.preview
	case "basket":
		return rt.basket
	case "prepare":
		return rt.prepare
	case "order":
		return rt.order
	case "compatibility":
		return rt.compat
	}
	return nil
}

// wireBody is the one error body: the wire code and a fixed description.
func (rt *Routes) refuse(w http.ResponseWriter, route string, rf *Refusal) {
	if rf == nil || rf.Err == nil {
		rf = refusal(glovo.CodeUnavailable, "invariant")
	}
	if rf.Unauthenticated {
		rt.note(Refused{Route: route, Code: rf.Err.Code, Wire: "not_authorized", Status: http.StatusUnauthorized, Reason: rf.Reason})
		glovo.WriteUnauthenticated(w, "")
		return
	}
	status, wire := rt.doc.WireFor(string(rf.Err.Code))
	desc := rf.Err.Description
	if wire == "dependency_unavailable" {
		desc = glovo.Refuse(glovo.CodeUnavailable).Description
	}
	if status == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", "60")
	}
	rt.note(Refused{Route: route, Code: rf.Err.Code, Wire: wire, Status: status, Reason: rf.Reason})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	b, _ := json.Marshal(map[string]string{"error": wire, "error_description": desc})
	_, _ = w.Write(b)
}

func (rt *Routes) note(e Refused) {
	if rt.OnRefused != nil {
		rt.OnRefused(e)
	}
}

// pipeline is the order of every route: facade aggregate limit, subject
// verification, scope, per-subject limits, scope ref, request shape, then the
// handler. Each step refuses before the next one runs.
func (rt *Routes) pipeline(route contract.Route, h joinHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rt.aggreg.OnLimit(w, r, "glovo-facade-total") {
			rt.refuse(w, route.ID, refusal(glovo.CodeRateLimited, "rate_limited"))
			return
		}
		var sub Subject
		if route.Scope != "facade_identity" {
			s, rf := rt.Verifier.Verify(r)
			if rf != nil {
				rt.refuse(w, route.ID, rf)
				return
			}
			sub = s
			if route.Scope == "glovo:read" || route.Scope == "glovo:basket:prepare" {
				if !sub.HasScope(route.Scope) {
					rt.refuse(w, route.ID, refusal(glovo.CodeScopeUnsupported, "insufficient_scope"))
					return
				}
			}
			if rt.perSubject.OnLimit(w, r, "s:"+sub.PrincipalID) || (isWrite(route) && rt.writes.OnLimit(w, r, "w:"+sub.PrincipalID)) {
				rt.refuse(w, route.ID, refusal(glovo.CodeRateLimited, "rate_limited"))
				return
			}
			if route.NeedsScopeRef {
				if rf := rt.Refs.Validate(r.Context(), r.Header.Get(ScopeRefHeader), sub); rf != nil {
					rt.refuse(w, route.ID, rf)
					return
				}
			}
		}
		if len(r.URL.RawQuery) > 0 {
			rt.refuse(w, route.ID, refusal(glovo.CodeInvalidRequest, "invalid_request"))
			return
		}
		status, body, replayed, rf := h(w, r, sub, route)
		if rf != nil {
			rt.refuse(w, route.ID, rf)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if replayed {
			w.Header().Set(IdempotentReplayedHdr, "true")
		}
		w.WriteHeader(status)
		_, _ = w.Write(body)
	})
}

// isWrite reports the routes that count against the writes limit.
func isWrite(route contract.Route) bool { return route.Idempotent }

// decode reads a strict JSON body: a size bound, no unknown field, one value
// and nothing after it. dst nil means the body must be empty.
func decode(r *http.Request, dst any) *Refusal {
	bad := refusal(glovo.CodeInvalidRequest, "invalid_request")
	data, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, bodyMax))
	if err != nil {
		return bad
	}
	if dst == nil {
		if len(bytes.TrimSpace(data)) != 0 {
			return bad
		}
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return bad
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return bad
	}
	return nil
}

// idempotencyKey enforces header_and_body_must_match and the key pattern.
func idempotencyKey(r *http.Request, bodyKey string) (string, *Refusal) {
	bad := refusal(glovo.CodeInvalidRequest, "invalid_request")
	h := r.Header.Get(IdempotencyKeyHeader)
	if h == "" || h != bodyKey || !idempotencyKeyRE.MatchString(h) {
		return "", bad
	}
	return h, nil
}

func marshal(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func (rt *Routes) resolve(_ http.ResponseWriter, r *http.Request, sub Subject, _ contract.Route) (int, []byte, bool, *Refusal) {
	var in struct{}
	if rf := decode(r, &in); rf != nil {
		return 0, nil, false, rf
	}
	ref, exp, err := rt.Refs.Issue(r.Context(), sub)
	if err != nil {
		var rf *Refusal
		if errors.As(err, &rf) {
			return 0, nil, false, rf
		}
		return 0, nil, false, toRefusal(err, "scope_ref")
	}
	return http.StatusOK, marshal(map[string]string{"scope_ref": ref, "tenant": sub.Tenant, "expires_at": ts(exp)}), false, nil
}

func (rt *Routes) joinScope(sub Subject) connect.JoinScope {
	return connect.JoinScope{Tenant: sub.Tenant, PrincipalID: sub.PrincipalID, InstallRevision: sub.InstallRevision}
}

func (rt *Routes) connection(_ http.ResponseWriter, r *http.Request, sub Subject, _ contract.Route) (int, []byte, bool, *Refusal) {
	if rf := decode(r, nil); rf != nil {
		return 0, nil, false, rf
	}
	if rt.Connect == nil {
		return 0, nil, false, refusal(glovo.CodeNotReady, "not_ready:connect")
	}
	c, err := rt.Connect.Current(r.Context(), rt.joinScope(sub))
	if err != nil {
		rf := toRefusal(err, "connection")
		if errors.Is(rf, glovo.Refuse(glovo.CodeNotFound)) {
			return 0, nil, false, refusal(glovo.CodeNoConnection, "connection_not_found")
		}
		return 0, nil, false, rf
	}
	if c == nil || c.State == glovo.Failed {
		return 0, nil, false, refusal(glovo.CodeNoConnection, "connection_not_found")
	}
	body := map[string]string{"connection_state": string(c.State), "connection_id": c.ConnectionID}
	if c.ExpiresAt != nil {
		body["expires_at"] = ts(*c.ExpiresAt)
	}
	return http.StatusOK, marshal(body), false, nil
}

func (rt *Routes) connect(_ http.ResponseWriter, r *http.Request, sub Subject, _ contract.Route) (int, []byte, bool, *Refusal) {
	var in struct {
		Key string `json:"idempotency_key"`
	}
	if rf := decode(r, &in); rf != nil {
		return 0, nil, false, rf
	}
	key, rf := idempotencyKey(r, in.Key)
	if rf != nil {
		return 0, nil, false, rf
	}
	if rt.Connect == nil {
		return 0, nil, false, refusal(glovo.CodeNotReady, "not_ready:connect")
	}
	out, err := rt.Connect.Connect(r.Context(), rt.joinScope(sub), key)
	if err != nil {
		return 0, nil, false, toRefusal(err, "connect")
	}
	if out == nil || out.Connection == nil || out.HandoffURL == "" || out.Connection.State != glovo.PendingHandoff {
		// A replay whose connection no longer waits for a handoff has no URL
		// to give: the client reads GET /connection for the live state.
		return 0, nil, false, refusal(glovo.CodeConnectionExists, "connection_not_pending")
	}
	return http.StatusOK, marshal(map[string]string{
		"connection_id": out.Connection.ConnectionID, "state": string(glovo.PendingHandoff),
		"handoff_url": out.HandoffURL, "expires_at": ts(out.HandoffExpiresAt),
	}), out.Replayed, nil
}

func (rt *Routes) orders(_ http.ResponseWriter, r *http.Request, sub Subject, _ contract.Route) (int, []byte, bool, *Refusal) {
	var in struct {
		Limit  *int   `json:"limit"`
		Cursor string `json:"cursor"`
	}
	if rf := decode(r, &in); rf != nil {
		return 0, nil, false, rf
	}
	limit := 0
	if in.Limit != nil {
		limit = *in.Limit
		if limit < 1 || limit > 20 {
			return 0, nil, false, refusal(glovo.CodeInvalidRequest, "invalid_request")
		}
	}
	if rt.Reader == nil {
		return 0, nil, false, refusal(glovo.CodeNotReady, "not_ready:reader")
	}
	v, rf := rt.Reader.History(r.Context(), sub, limit, in.Cursor)
	if rf != nil {
		return 0, nil, false, rf
	}
	body := struct {
		Orders     []HistoryOrder `json:"orders"`
		NextCursor string         `json:"next_cursor,omitempty"`
	}{Orders: v.Orders, NextCursor: v.NextCursor}
	if body.Orders == nil {
		body.Orders = []HistoryOrder{}
	}
	return http.StatusOK, marshal(body), false, nil
}

func (rt *Routes) preview(_ http.ResponseWriter, r *http.Request, sub Subject, _ contract.Route) (int, []byte, bool, *Refusal) {
	var in struct {
		OrderRef string `json:"order_ref"`
	}
	if rf := decode(r, &in); rf != nil {
		return 0, nil, false, rf
	}
	if rt.Reader == nil {
		return 0, nil, false, refusal(glovo.CodeNotReady, "not_ready:reader")
	}
	p, rf := rt.Reader.Preview(r.Context(), sub, in.OrderRef)
	if rf != nil {
		return 0, nil, false, rf
	}
	items, unavailable := p.Items, p.Unavailable
	if items == nil {
		items = []Item{}
	}
	if unavailable == nil {
		unavailable = []Item{}
	}
	return http.StatusOK, marshal(struct {
		PreviewID   string `json:"preview_id"`
		Items       []Item `json:"items"`
		Unavailable []Item `json:"unavailable_items"`
		Fingerprint string `json:"fingerprint"`
		ExpiresAt   string `json:"expires_at"`
	}{p.PreviewID, items, unavailable, p.Fingerprint, ts(p.ExpiresAt)}), false, nil
}

func (rt *Routes) basket(_ http.ResponseWriter, r *http.Request, sub Subject, _ contract.Route) (int, []byte, bool, *Refusal) {
	if rf := decode(r, nil); rf != nil {
		return 0, nil, false, rf
	}
	if rt.Reader == nil {
		return 0, nil, false, refusal(glovo.CodeNotReady, "not_ready:reader")
	}
	v, rf := rt.Reader.Basket(r.Context(), sub)
	if rf != nil {
		return 0, nil, false, rf
	}
	items := v.Items
	if items == nil {
		items = []Item{}
	}
	return http.StatusOK, marshal(struct {
		StoreName   string `json:"store_name,omitempty"`
		Items       []Item `json:"items"`
		TotalsLabel string `json:"totals_label"`
		Fingerprint string `json:"fingerprint"`
	}{v.StoreName, items, v.TotalsLabel, v.Fingerprint}), false, nil
}

func (rt *Routes) prepare(_ http.ResponseWriter, r *http.Request, sub Subject, _ contract.Route) (int, []byte, bool, *Refusal) {
	var in struct {
		PreviewID string `json:"preview_id"`
		Key       string `json:"idempotency_key"`
	}
	if rf := decode(r, &in); rf != nil {
		return 0, nil, false, rf
	}
	key, rf := idempotencyKey(r, in.Key)
	if rf != nil {
		return 0, nil, false, rf
	}
	if in.PreviewID == "" {
		return 0, nil, false, refusal(glovo.CodeInvalidRequest, "invalid_request")
	}
	if rt.Prepare == nil {
		return 0, nil, false, refusal(glovo.CodeNotReady, "not_ready:prepare")
	}
	res, rf := rt.Prepare.Prepare(r.Context(), PrepareRequest{Tenant: sub.Tenant, PrincipalID: sub.PrincipalID, PreviewID: in.PreviewID, Key: key})
	if rf != nil {
		return 0, nil, false, rf
	}
	return http.StatusOK, res.WireBody(), res.Replayed, nil
}

func (rt *Routes) order(_ http.ResponseWriter, r *http.Request, sub Subject, _ contract.Route) (int, []byte, bool, *Refusal) {
	if rf := decode(r, nil); rf != nil {
		return 0, nil, false, rf
	}
	ref := chi.URLParam(r, "order_id")
	if !orderRefRE.MatchString(ref) {
		return 0, nil, false, refusal(glovo.CodeNotFound, "order_not_found")
	}
	if rt.Status == nil {
		return 0, nil, false, refusal(glovo.CodeNotReady, "not_ready:status")
	}
	state, outcome, rf := rt.Status.Status(r.Context(), sub.Tenant, sub.PrincipalID, ref)
	if rf != nil {
		return 0, nil, false, rf
	}
	return http.StatusOK, marshal(map[string]string{"state": state, "outcome": outcome}), false, nil
}

func (rt *Routes) compat(_ http.ResponseWriter, r *http.Request, _ Subject, _ contract.Route) (int, []byte, bool, *Refusal) {
	if rf := decode(r, nil); rf != nil {
		return 0, nil, false, rf
	}
	return http.StatusOK, rt.Readiness.Check(r.Context()).JSON(), false, nil
}
