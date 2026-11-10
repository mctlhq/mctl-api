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

package glovobasket

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/scope"
)

// Tool names. There is no approve tool: an approval is decided only by the
// owner through POST /api/v1/action-approvals/{id}/decision.
const (
	ToolListProducts    = "glovo_list_products"
	ToolCreateBasket    = "glovo_create_basket"
	ToolUpdateBasket    = "glovo_update_basket"
	ToolGetBasket       = "glovo_get_basket"
	ToolRequestApproval = "glovo_request_approval"
	ToolApprovalStatus  = "glovo_approval_status"
)

// Defaults of Config.
const (
	DefaultMaxBaskets     = 20
	DefaultCallsPerMinute = 60
	DefaultApprovalTTL    = 15 * time.Minute
	// MaxRequestBytes bounds one MCP request body.
	MaxRequestBytes = 64 << 10
)

// Config is the basket MCP. Store and Resolver are required.
type Config struct {
	Store    Store
	Resolver *scope.Resolver
	// MaxBaskets per owner and team; 0 is DefaultMaxBaskets.
	MaxBaskets int
	// CallsPerMinute per principal; 0 is DefaultCallsPerMinute.
	CallsPerMinute int
	// ApprovalTTL of a requested approval; 0 is DefaultApprovalTTL.
	ApprovalTTL time.Duration
	// Now is the limiter clock; nil is time.Now.
	Now func() time.Time
	// Logger receives the audit lines; nil is slog.Default().
	Logger *slog.Logger
	// ApprovalPageBaseURL is the https origin of the owner approval page
	// (mctl-api#1007), e.g. https://api.mctl.ai. When set,
	// glovo_request_approval also returns approval_url =
	// <origin>/glovo/basket/approvals/<approval_ref>, the link the client
	// shows the owner. The link carries no secret and grants nothing. Empty
	// means no page is mounted and no URL is returned.
	ApprovalPageBaseURL string
}

// ApprovalPagePath is the owner approval page's path prefix (mctl-api#1007).
const ApprovalPagePath = "/glovo/basket/approvals/"

// approvalPageOrigin checks that base is a bare https origin and returns it
// without a trailing slash.
func approvalPageOrigin(base string) (string, error) {
	if base == "" {
		return "", nil
	}
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") ||
		u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("glovo basket: approval page base URL must be an https origin, got %q", base)
	}
	return "https://" + u.Host, nil
}

type service struct {
	cfg     Config
	limiter *limiter
}

// NewHandler returns the Streamable HTTP MCP endpoint. Every request is
// size-limited and resolved through scope.Resolve (grant, membership,
// allowlist) before any tool runs; the caller mounts it behind the auth
// middleware and an audience gate that admits the Glovo audience only.
func NewHandler(cfg Config) (http.Handler, error) {
	if cfg.Resolver == nil {
		return nil, errors.New("glovo basket: store and resolver are required")
	}
	mcpSrv, err := newMCPServer(cfg)
	if err != nil {
		return nil, err
	}
	stream := server.NewStreamableHTTPServer(mcpSrv,
		server.WithStateLess(true),
		server.WithHTTPContextFunc(func(ctx context.Context, r *http.Request) context.Context {
			if sc, ok := scope.FromContext(r.Context()); ok {
				return context.WithValue(ctx, scopeKey{}, sc)
			}
			return ctx
		}))
	h := scope.RequireScope(cfg.Resolver)(stream)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > MaxRequestBytes {
			glovo.WriteError(w, glovo.Refuse(glovo.CodeInvalidRequest))
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBytes)
		h.ServeHTTP(w, r)
	}), nil
}

// newMCPServer builds the MCP server with the six tools. A tool reads the
// caller from the context (scopeKey), which only NewHandler's RequireScope
// sets on the HTTP path.
func newMCPServer(cfg Config) (*server.MCPServer, error) {
	if glovo.IsNil(cfg.Store) {
		return nil, errors.New("glovo basket: store and resolver are required")
	}
	if cfg.MaxBaskets <= 0 {
		cfg.MaxBaskets = DefaultMaxBaskets
	}
	if cfg.CallsPerMinute <= 0 {
		cfg.CallsPerMinute = DefaultCallsPerMinute
	}
	if cfg.ApprovalTTL <= 0 {
		cfg.ApprovalTTL = DefaultApprovalTTL
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	origin, err := approvalPageOrigin(cfg.ApprovalPageBaseURL)
	if err != nil {
		return nil, err
	}
	cfg.ApprovalPageBaseURL = origin
	s := &service{cfg: cfg, limiter: &limiter{per: cfg.CallsPerMinute, now: cfg.Now, seen: map[string]*window{}}}
	mcpSrv := server.NewMCPServer("mctl-glovo-basket", "1.0.0", server.WithToolCapabilities(false), server.WithRecovery())
	s.register(mcpSrv)
	return mcpSrv, nil
}

type scopeKey struct{}

type toolError struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

func errorResult(e *glovo.Error) *mcp.CallToolResult {
	raw, _ := json.Marshal(toolError{Error: string(e.Code), Description: e.Description})
	return mcp.NewToolResultError(string(raw))
}

func okResult(v any) *mcp.CallToolResult {
	raw, err := json.Marshal(v)
	if err != nil {
		return errorResult(glovo.Refuse(glovo.CodeUnavailable))
	}
	return mcp.NewToolResultStructured(v, string(raw))
}

// decodeArgs decodes the tool arguments strictly: an unknown field (a price,
// say) is a refusal, not ignored.
func decodeArgs(req mcp.CallToolRequest, v any) error {
	raw, err := json.Marshal(req.GetArguments())
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

type handlerFunc func(ctx context.Context, o Owner, req mcp.CallToolRequest, a *auditLine) (any, error)

type auditLine struct {
	basketID string
	revision int64
	ref      string
}

// wrap resolves the owner, applies the per-principal quota, runs the tool and
// writes one audit line: ids, enums and the outcome only, never a token, a
// basket body or an argument.
func (s *service) wrap(name string, fn handlerFunc) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		sc, ok := ctx.Value(scopeKey{}).(Scope)
		if !ok || sc.PrincipalID == "" || sc.Tenant == "" {
			return errorResult(glovo.Refuse(glovo.CodeNotAuthorized)), nil
		}
		o := Owner{Tenant: sc.Tenant, PrincipalID: sc.PrincipalID}
		var a auditLine
		outcome := "ok"
		defer func() {
			s.cfg.Logger.Info("glovo_basket.tool", "tool", name, "principal_id", o.PrincipalID, "tenant", o.Tenant,
				"grant_id", sc.GrantID, "basket_id", a.basketID, "revision", a.revision, "approval_ref", a.ref, "outcome", outcome)
		}()
		if !s.limiter.allow(o.PrincipalID) {
			outcome = string(glovo.CodeRateLimited)
			return errorResult(glovo.Refuse(glovo.CodeRateLimited)), nil
		}
		v, err := fn(ctx, o, req, &a)
		if err != nil {
			ge := toGlovoError(err)
			outcome = string(ge.Code)
			if ge.Code == glovo.CodeUnavailable {
				s.cfg.Logger.Error("glovo_basket.tool_failed", "tool", name, "err", err)
			}
			return errorResult(ge), nil
		}
		return okResult(v), nil
	}
}

// Scope is the resolved caller; an alias so tests can set it.
type Scope = scope.Scope

func toGlovoError(err error) *glovo.Error {
	var ge *glovo.Error
	switch {
	case IsInvalid(err):
		e := glovo.Refuse(glovo.CodeInvalidRequest)
		e.Description = err.Error()
		return e
	case errors.As(err, &ge) && glovo.Registered(ge.Code):
		return glovo.Refuse(ge.Code)
	}
	return glovo.Refuse(glovo.CodeUnavailable)
}

func invalidArgs() error { return invalidf("the arguments do not match the tool's input schema") }

func (s *service) register(m *server.MCPServer) {
	readOnly := []mcp.ToolOption{mcp.WithReadOnlyHintAnnotation(true), mcp.WithDestructiveHintAnnotation(false), mcp.WithOpenWorldHintAnnotation(false)}
	write := []mcp.ToolOption{mcp.WithReadOnlyHintAnnotation(false), mcp.WithDestructiveHintAnnotation(false), mcp.WithOpenWorldHintAnnotation(false)}
	opts := func(base []mcp.ToolOption, more ...mcp.ToolOption) []mcp.ToolOption {
		return append(append([]mcp.ToolOption(nil), base...), more...)
	}
	basketID := mcp.WithString("basket_id", mcp.Required(), mcp.Pattern(`^gbk_[A-Za-z0-9]{26}$`), mcp.Description("The basket id from glovo_create_basket."))
	expected := mcp.WithInteger("expected_revision", mcp.Required(), mcp.Min(1), mcp.Description("The basket's current revision; a stale one is refused."))

	m.AddTool(mcp.NewTool(ToolListProducts, opts(readOnly,
		mcp.WithDescription("List the synthetic catalog (item codes, names, unit prices in minor units). Nothing here is a real store."))...),
		s.wrap(ToolListProducts, func(context.Context, Owner, mcp.CallToolRequest, *auditLine) (any, error) {
			return map[string]any{"store_ref": StoreRef, "currency": Currency, "products": Catalog()}, nil
		}))

	m.AddTool(mcp.NewTool(ToolCreateBasket, opts(write, mcp.WithIdempotentHintAnnotation(true),
		mcp.WithDescription("Create an empty basket, or return the one already created with this client_key."),
		mcp.WithString("client_key", mcp.Required(), mcp.MinLength(1), mcp.MaxLength(MaxClientKeyLen),
			mcp.Description("Idempotency key chosen by the client.")))...),
		s.wrap(ToolCreateBasket, func(ctx context.Context, o Owner, req mcp.CallToolRequest, a *auditLine) (any, error) {
			var in struct {
				ClientKey string `json:"client_key"`
			}
			if err := decodeArgs(req, &in); err != nil || in.ClientKey == "" || len(in.ClientKey) > MaxClientKeyLen {
				return nil, invalidArgs()
			}
			b, created, err := s.cfg.Store.Create(ctx, o, in.ClientKey, s.cfg.MaxBaskets)
			if err != nil {
				return nil, err
			}
			a.basketID, a.revision = b.ID, b.Current.Revision
			return map[string]any{"basket": b, "created": created}, nil
		}))

	m.AddTool(mcp.NewTool(ToolUpdateBasket, opts(write,
		mcp.WithDescription("Change a basket: each op is add, set or remove of a catalog item. The server prices every line; "+
			"the result is a new revision. Any approval of an earlier revision does not cover it."),
		basketID, expected,
		mcp.WithArray("ops", mcp.Required(), mcp.MinItems(1), mcp.MaxItems(MaxOpsPerUpdate), mcp.Items(map[string]any{
			"type": "object", "additionalProperties": false, "required": []string{"op", "item_code"},
			"properties": map[string]any{
				"op":        map[string]any{"type": "string", "enum": []string{"add", "set", "remove"}},
				"item_code": map[string]any{"type": "string"},
				"quantity":  map[string]any{"type": "integer", "minimum": 0, "maximum": MaxQuantity},
			},
		})))...),
		s.wrap(ToolUpdateBasket, func(ctx context.Context, o Owner, req mcp.CallToolRequest, a *auditLine) (any, error) {
			var in struct {
				BasketID         string `json:"basket_id"`
				ExpectedRevision int64  `json:"expected_revision"`
				Ops              []Op   `json:"ops"`
			}
			if err := decodeArgs(req, &in); err != nil {
				return nil, invalidArgs()
			}
			a.basketID = in.BasketID
			b, err := s.cfg.Store.Update(ctx, o, in.BasketID, in.ExpectedRevision, in.Ops)
			if err != nil {
				return nil, err
			}
			a.revision = b.Current.Revision
			return map[string]any{"basket": b}, nil
		}))

	m.AddTool(mcp.NewTool(ToolGetBasket, opts(readOnly,
		mcp.WithDescription("Read one of your baskets at its current revision."), basketID)...),
		s.wrap(ToolGetBasket, func(ctx context.Context, o Owner, req mcp.CallToolRequest, a *auditLine) (any, error) {
			var in struct {
				BasketID string `json:"basket_id"`
			}
			if err := decodeArgs(req, &in); err != nil {
				return nil, invalidArgs()
			}
			a.basketID = in.BasketID
			b, err := s.cfg.Store.Get(ctx, o, in.BasketID)
			if err != nil {
				return nil, err
			}
			a.revision = b.Current.Revision
			return map[string]any{"basket": b}, nil
		}))

	m.AddTool(mcp.NewTool(ToolRequestApproval, opts(write, mcp.WithIdempotentHintAnnotation(true),
		mcp.WithDescription("Ask the basket's owner to approve its current revision. Returns an approval_ref and, when the "+
			"approval page is enabled, an approval_url to show the owner; the owner decides outside this tool set. "+
			"Nothing is ordered."), basketID, expected)...),
		s.wrap(ToolRequestApproval, func(ctx context.Context, o Owner, req mcp.CallToolRequest, a *auditLine) (any, error) {
			var in struct {
				BasketID         string `json:"basket_id"`
				ExpectedRevision int64  `json:"expected_revision"`
			}
			if err := decodeArgs(req, &in); err != nil {
				return nil, invalidArgs()
			}
			a.basketID, a.revision = in.BasketID, in.ExpectedRevision
			r, err := s.cfg.Store.RequestApproval(ctx, o, in.BasketID, in.ExpectedRevision, s.cfg.ApprovalTTL)
			if err != nil {
				return nil, err
			}
			a.ref = r.ApprovalRef
			if s.cfg.ApprovalPageBaseURL != "" {
				out := *r
				out.ApprovalURL = s.cfg.ApprovalPageBaseURL + ApprovalPagePath + url.PathEscape(r.ApprovalRef)
				return &out, nil
			}
			return r, nil
		}))

	m.AddTool(mcp.NewTool(ToolApprovalStatus, opts(readOnly,
		mcp.WithDescription("Read an approval: pending, approved, rejected or expired, and whether it covers the basket's current revision."),
		mcp.WithString("approval_ref", mcp.Required(), mcp.Pattern(`^aar_[A-Za-z0-9]{1,64}$`)))...),
		s.wrap(ToolApprovalStatus, func(ctx context.Context, o Owner, req mcp.CallToolRequest, a *auditLine) (any, error) {
			var in struct {
				ApprovalRef string `json:"approval_ref"`
			}
			if err := decodeArgs(req, &in); err != nil {
				return nil, invalidArgs()
			}
			a.ref = in.ApprovalRef
			st, err := s.cfg.Store.ApprovalStatus(ctx, o, in.ApprovalRef)
			if err != nil {
				return nil, err
			}
			a.basketID, a.revision = st.BasketID, st.Revision
			return st, nil
		}))
}

// limiter is a fixed one-minute window per principal.
type limiter struct {
	mu   sync.Mutex
	per  int
	now  func() time.Time
	seen map[string]*window
}

type window struct {
	start time.Time
	n     int
}

func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if len(l.seen) > 10000 {
		for k, w := range l.seen {
			if now.Sub(w.start) >= time.Minute {
				delete(l.seen, k)
			}
		}
	}
	w := l.seen[key]
	if w == nil || now.Sub(w.start) >= time.Minute {
		w = &window{start: now}
		l.seen[key] = w
	}
	if w.n >= l.per {
		return false
	}
	w.n++
	return true
}
