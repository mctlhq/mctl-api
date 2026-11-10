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

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/httprate"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/bridge"
	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/control"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// The Glovo control routes (mctl-api#985) are the four internal calls of the
// DevLoop control activities: dispatch and cancel an order, read its command
// and read its approval. They are mounted only when glovo.ControlDefault is
// open (a const that is false in every release build) and
// MCTL_GLOVO_CONTROL_ENABLED is set. Only the control-worker principal reaches
// them, and the tenants it may address are server-side configuration, never a
// field of a request. Nothing in a body is a payload, a basket, an endpoint or a
// credential: the provider payload is built from the order index.

// glovoControlRoutes are the four routes the control worker may call.
var glovoControlRoutes = []struct {
	method string
	path   *regexp.Regexp
}{
	{http.MethodPost, regexp.MustCompile(`^/api/v1/internal/glovo/orders/[^/]+/dispatch$`)},
	{http.MethodPost, regexp.MustCompile(`^/api/v1/internal/glovo/orders/[^/]+/cancel$`)},
	{http.MethodGet, regexp.MustCompile(`^/api/v1/internal/glovo/commands/[^/]+$`)},
	{http.MethodGet, regexp.MustCompile(`^/api/v1/internal/glovo/approvals/[^/]+$`)},
}

var (
	glovoControlOrderRefRE    = regexp.MustCompile(`^ordr_[A-Za-z0-9]{16,40}$`)
	glovoControlApprovalRefRE = regexp.MustCompile(`^aar_[A-Za-z0-9]{16,40}$`)
	glovoControlFingerprintRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// glovoControlPerMinute is the default per-(principal, tenant) budget.
const glovoControlPerMinute = 120

// glovoControlBodyMax bounds a control request body; the largest is two refs.
const glovoControlBodyMax = 1024

// GlovoControlService is what the control routes call: *control.Dispatcher in
// production, a fake in the HTTP-layer tests.
type GlovoControlService interface {
	Ready(ctx context.Context) error
	TenantFor(ctx context.Context, tenants []string, ref string) string
	Dispatch(ctx context.Context, tenants []string, orderRef, approvalRef, fingerprint string) (*control.Result, error)
	Cancel(ctx context.Context, tenants []string, orderRef string) (*control.Result, error)
	ReadCommand(ctx context.Context, tenants []string, commandID string) (*control.CommandView, error)
	ReadApproval(ctx context.Context, tenants []string, approvalRef string) (*workitems.GlovoApprovalStatus, error)
}

var _ GlovoControlService = (*control.Dispatcher)(nil)

// GlovoControlRoutes configures the control routes. A nil value, a closed Open
// or a false Enabled leaves every route unmounted (404).
type GlovoControlRoutes struct {
	// Open is glovo.ControlDefault.Open: the build-time gate.
	Open bool
	// Enabled is MCTL_GLOVO_CONTROL_ENABLED.
	Enabled bool
	// Tenants is the control worker's server-side tenant upper bound.
	Tenants []string
	// Dispatcher serves the routes; nil, or not ready, answers 503 not_ready.
	Dispatcher GlovoControlService
	// PerMinute is the per-(principal, tenant) budget; zero is the default.
	PerMinute int

	once    sync.Once
	limiter *httprate.RateLimiter
}

// mounted reports whether the routes exist at all.
func (g *GlovoControlRoutes) mounted() bool { return g != nil && g.Open && g.Enabled }

func (g *GlovoControlRoutes) rateLimiter() *httprate.RateLimiter {
	g.once.Do(func() {
		n := g.PerMinute
		if n <= 0 {
			n = glovoControlPerMinute
		}
		g.limiter = httprate.NewRateLimiter(n, time.Minute)
	})
	return g.limiter
}

// glovoControlWorkerGate confines the control worker to the four control
// routes: on every other route, or with another method, it answers 403
// not_authorized before any handler runs.
func (h *Handlers) glovoControlWorkerGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if user := auth.UserFromContext(r.Context()); user.IsGlovoControlWorker() && !glovoControlRoute(r) {
			glovoRouteRefusals.WithLabelValues("control_gate", string(glovo.CodeNotAuthorized)).Inc()
			glovo.WriteError(w, glovo.Refuse(glovo.CodeNotAuthorized))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func glovoControlRoute(r *http.Request) bool {
	for _, c := range glovoControlRoutes {
		if r.Method == c.method && c.path.MatchString(r.URL.Path) {
			return true
		}
	}
	return false
}

// requireGlovoControlWorker admits only the control-worker principal: not an
// admin, not the service token, not a bridge provider, not the Glovo worker.
func requireGlovoControlWorker(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		if user == nil || !user.IsGlovoControlWorker() || !user.HasPermission(auth.PermissionGlovoControlDispatch) {
			glovoRouteRefusals.WithLabelValues("control_require", string(glovo.CodeNotAuthorized)).Inc()
			glovo.WriteError(w, glovo.Refuse(glovo.CodeNotAuthorized))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (h *Handlers) glovoControl() *GlovoControlRoutes { return h.opts.GlovoControl }

// glovoControlCall is the common prefix of the four handlers: not_ready before
// the body is read, the ref check, and the per-(principal, tenant) bucket.
// ok false means the response was written.
func (h *Handlers) glovoControlCall(w http.ResponseWriter, r *http.Request, route, ref string, refOK func(string) bool) (GlovoControlService, []string, bool) {
	g := h.glovoControl()
	if !g.mounted() {
		h.glovoControlFail(w, r, route, ref, glovo.Refuse(glovo.CodeNotReady), nil)
		return nil, nil, false
	}
	if glovo.IsNil(g.Dispatcher) {
		h.glovoControlFail(w, r, route, ref, glovo.Refuse(glovo.CodeNotReady), nil)
		return nil, nil, false
	}
	if err := g.Dispatcher.Ready(r.Context()); err != nil {
		// Any failed readiness answer, including one that could not be
		// observed, is not_ready; the cause stays in the audit reason.
		h.glovoControlFail(w, r, route, ref, fmt.Errorf("%w: %v", glovo.Refuse(glovo.CodeNotReady), err), nil)
		return nil, nil, false
	}
	if !refOK(ref) {
		h.glovoControlFail(w, r, route, ref, glovo.Refuse(glovo.CodeInvalidRequest), nil)
		return nil, nil, false
	}
	user := auth.UserFromContext(r.Context())
	tenant := g.Dispatcher.TenantFor(r.Context(), g.Tenants, ref)
	if g.rateLimiter().OnLimit(w, r, user.ID+"|"+tenant) {
		h.glovoControlFail(w, r, route, ref, glovo.Refuse(glovo.CodeRateLimited), nil)
		return nil, nil, false
	}
	return g.Dispatcher, g.Tenants, true
}

// glovoControlFail writes the closed refusal and records the audit row: ids
// and codes only, with the internal reason in the message.
func (h *Handlers) glovoControlFail(w http.ResponseWriter, r *http.Request, route, ref string, err error, params map[string]string) {
	ge := control.Refusal(err)
	reason := control.Reason(err)
	glovoRouteRefusals.WithLabelValues(route, string(ge.Code)).Inc()
	if ge.Code == glovo.CodeUnavailable {
		slog.Warn("glovo control route failed", "route", route, "code", string(ge.Code), "reason", reason)
	}
	h.glovoControlAudit(r, route, "refused", ref, params, string(ge.Code), reason)
	glovo.WriteError(w, ge)
}

func (h *Handlers) glovoControlAudit(r *http.Request, route, status, ref string, params map[string]string, code, reason string) {
	p := map[string]string{"route": route}
	switch {
	case strings.HasPrefix(ref, "ordr_"):
		p["order_ref"] = ref
	case strings.HasPrefix(ref, "cmd_"):
		p["command_id"] = ref
	case strings.HasPrefix(ref, "aar_"):
		p["approval_ref"] = ref
	}
	for k, v := range params {
		p[k] = v
	}
	if len(reason) > 200 {
		reason = reason[:200]
	}
	userID := ""
	if u := auth.UserFromContext(r.Context()); u != nil {
		userID = u.ID
	}
	h.logAudit(r, audit.Entry{
		UserID: userID, Operation: "glovo.control." + route, Parameters: p, Status: status,
		RiskLevel: "high", RefusalCode: code, Message: reason,
	})
}

// glovoControlBody reads a bounded body, refuses a duplicate top-level key and
// decodes it strictly (unknown fields are invalid_request).
func glovoControlBody(w http.ResponseWriter, r *http.Request, dst any, allowEmpty bool) error {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, glovoControlBodyMax))
	if err != nil {
		return err
	}
	if err := rejectDuplicateKeys(body); err != nil {
		return err
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	return readStrictJSON(r, dst, allowEmpty)
}

// rejectDuplicateKeys refuses an object with a repeated top-level key, which
// encoding/json would otherwise resolve silently to the last one.
func rejectDuplicateKeys(body []byte) error {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return errors.New("not an object")
	}
	seen := map[string]bool{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := t.(string)
		if !ok || seen[key] {
			return errors.New("duplicate or malformed key")
		}
		seen[key] = true
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return err
		}
	}
	return nil
}

func writeGlovoControlJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(v)
}

// GlovoControlDispatch handles POST /api/v1/internal/glovo/orders/{order_ref}/dispatch.
func (h *Handlers) GlovoControlDispatch(w http.ResponseWriter, r *http.Request) {
	const route = "dispatch"
	ref := chi.URLParam(r, "order_ref")
	d, tenants, ok := h.glovoControlCall(w, r, route, ref, glovoControlOrderRefRE.MatchString)
	if !ok {
		return
	}
	var req struct {
		ApprovalRef string `json:"approval_ref"`
		Fingerprint string `json:"fingerprint"`
	}
	if err := glovoControlBody(w, r, &req, false); err != nil ||
		!glovoControlApprovalRefRE.MatchString(req.ApprovalRef) || !glovoControlFingerprintRE.MatchString(req.Fingerprint) {
		h.glovoControlFail(w, r, route, ref, glovo.Refuse(glovo.CodeInvalidRequest), nil)
		return
	}
	res, err := d.Dispatch(r.Context(), tenants, ref, req.ApprovalRef, req.Fingerprint)
	if err != nil {
		h.glovoControlFail(w, r, route, ref, err, map[string]string{"approval_ref": req.ApprovalRef})
		return
	}
	if res.Replayed {
		w.Header().Set("Idempotent-Replayed", "true")
	}
	h.glovoControlAudit(r, route, "succeeded", ref, map[string]string{
		"approval_ref": req.ApprovalRef, "command_id": res.CommandID, "replayed": boolString(res.Replayed)}, "", "")
	writeGlovoControlJSON(w, map[string]string{
		"command_id": res.CommandID, "order_state": res.OrderState, "effect_state": res.EffectState})
}

// GlovoControlCancel handles POST /api/v1/internal/glovo/orders/{order_ref}/cancel.
func (h *Handlers) GlovoControlCancel(w http.ResponseWriter, r *http.Request) {
	const route = "cancel"
	ref := chi.URLParam(r, "order_ref")
	d, tenants, ok := h.glovoControlCall(w, r, route, ref, glovoControlOrderRefRE.MatchString)
	if !ok {
		return
	}
	var req struct{}
	if err := glovoControlBody(w, r, &req, true); err != nil {
		h.glovoControlFail(w, r, route, ref, glovo.Refuse(glovo.CodeInvalidRequest), nil)
		return
	}
	res, err := d.Cancel(r.Context(), tenants, ref)
	if err != nil {
		h.glovoControlFail(w, r, route, ref, err, nil)
		return
	}
	h.glovoControlAudit(r, route, "succeeded", ref, map[string]string{"command_id": res.CommandID, "order_state": res.OrderState}, "", "")
	body := map[string]string{"order_state": res.OrderState, "effect_state": res.EffectState}
	if res.CommandID != "" {
		body["command_id"] = res.CommandID
	}
	writeGlovoControlJSON(w, body)
}

// GlovoControlReadCommand handles GET /api/v1/internal/glovo/commands/{command_id}.
func (h *Handlers) GlovoControlReadCommand(w http.ResponseWriter, r *http.Request) {
	const route = "read_command"
	ref := chi.URLParam(r, "command_id")
	d, tenants, ok := h.glovoControlCall(w, r, route, ref, bridge.IsCommandID)
	if !ok {
		return
	}
	v, err := d.ReadCommand(r.Context(), tenants, ref)
	if err != nil {
		h.glovoControlFail(w, r, route, ref, err, nil)
		return
	}
	h.glovoControlAudit(r, route, "succeeded", ref, map[string]string{"order_ref": v.OrderRef}, "", "")
	body := map[string]string{
		"command_id": v.CommandID, "order_ref": v.OrderRef, "status": v.Status, "effect_state": v.EffectState}
	for k, val := range map[string]string{
		"outcome": v.Outcome, "provider_effect": v.ProviderEffect, "error_code": v.ErrorCode, "result_digest": v.ResultDigest} {
		if val != "" {
			body[k] = val
		}
	}
	writeGlovoControlJSON(w, body)
}

// GlovoControlReadApproval handles GET /api/v1/internal/glovo/approvals/{approval_ref}.
func (h *Handlers) GlovoControlReadApproval(w http.ResponseWriter, r *http.Request) {
	const route = "read_approval"
	ref := chi.URLParam(r, "approval_ref")
	d, tenants, ok := h.glovoControlCall(w, r, route, ref, glovoControlApprovalRefRE.MatchString)
	if !ok {
		return
	}
	st, err := d.ReadApproval(r.Context(), tenants, ref)
	if err != nil {
		h.glovoControlFail(w, r, route, ref, err, nil)
		return
	}
	h.glovoControlAudit(r, route, "succeeded", ref, map[string]string{"order_ref": st.OrderRef}, "", "")
	writeGlovoControlJSON(w, map[string]string{
		"approval_ref": st.ApprovalRef, "order_ref": st.OrderRef, "state": st.State,
		"expires_at": st.ExpiresAt.UTC().Format(time.RFC3339)})
}

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
