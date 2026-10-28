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

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/mctlhq/mctl-api/internal/auth"
)

// Tenant support agent over A2A 1.0 (mctl-api#814, support S1d). Two thin
// tools call mctl-support with a short-lived, support-audience access token
// that mctl-api mints for the caller's own principal (mctl-api#852). The
// caller's API token is never sent. mctl-api adds no authority and uses no
// service credential; its only check is that the caller may act on the named
// tenant. mctl-support checks again.

const (
	supportA2AVersion   = "1.0"
	supportMaxBody      = 1 << 20
	supportMaxQuestion  = 8 << 10
	supportMaxTaskID    = 256
	supportMinWait      = 5 * time.Second
	supportMaxWait      = 90 * time.Second
	supportDefaultWait  = 60 * time.Second
	supportDefaultPoll  = 2 * time.Second
	supportMinPoll      = 500 * time.Millisecond
	supportDefaultReqTO = 15 * time.Second
	supportMinReqTO     = time.Second

	supportDefaultTokenTTL = 11 * time.Minute
	supportMinTokenTTL     = 2 * time.Minute
	supportMaxTokenTTL     = 15 * time.Minute
	supportReadTokenCap    = 5 * time.Minute
)

// SupportConfig configures the support tools. BaseURL empty means not configured.
type SupportConfig struct {
	BaseURL        string
	Wait           time.Duration // single budget for the send and all polling
	PollInterval   time.Duration
	RequestTimeout time.Duration // cap on one GET /tasks/{id}
	TokenTTL       time.Duration // lifetime of the token minted for mctl_ask_support
}

// SetSupportConfig enables the support tools.
func (s *Server) SetSupportConfig(c SupportConfig) {
	c.BaseURL = strings.TrimRight(c.BaseURL, "/")
	if c.Wait <= 0 {
		c.Wait = supportDefaultWait
	}
	if c.PollInterval <= 0 {
		c.PollInterval = supportDefaultPoll
	}
	if c.RequestTimeout <= 0 {
		c.RequestTimeout = supportDefaultReqTO
	}
	if c.TokenTTL <= 0 {
		c.TokenTTL = supportDefaultTokenTTL
	}
	s.support.Store(&c)
}

// ParseSupportConfig reads SUPPORT_A2A_URL, SUPPORT_ASK_WAIT,
// SUPPORT_POLL_INTERVAL, SUPPORT_REQUEST_TIMEOUT and SUPPORT_TOKEN_TTL. An unset URL returns a
// zero config (not configured) and no error; a bad value is an error.
func ParseSupportConfig(getenv func(string) string) (SupportConfig, error) {
	raw := strings.TrimSpace(getenv("SUPPORT_A2A_URL"))
	if raw == "" {
		return SupportConfig{}, nil
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return SupportConfig{}, fmt.Errorf("SUPPORT_A2A_URL %q must be an absolute URL", raw)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopbackHost(u.Hostname()) {
			return SupportConfig{}, fmt.Errorf("SUPPORT_A2A_URL %q must be https unless the host is loopback", raw)
		}
	default:
		return SupportConfig{}, fmt.Errorf("SUPPORT_A2A_URL %q must be an http(s) URL", raw)
	}
	dur := func(name string, def time.Duration) (time.Duration, error) {
		v := strings.TrimSpace(getenv(name))
		if v == "" {
			return def, nil
		}
		d, err := time.ParseDuration(v)
		if err != nil {
			return 0, fmt.Errorf("%s %q is not a duration: %w", name, v, err)
		}
		return d, nil
	}
	cfg := SupportConfig{BaseURL: strings.TrimRight(raw, "/")}
	if cfg.Wait, err = dur("SUPPORT_ASK_WAIT", supportDefaultWait); err != nil {
		return SupportConfig{}, err
	}
	if cfg.Wait < supportMinWait || cfg.Wait > supportMaxWait {
		return SupportConfig{}, fmt.Errorf("SUPPORT_ASK_WAIT %s must be between %s and %s", cfg.Wait, supportMinWait, supportMaxWait)
	}
	if cfg.PollInterval, err = dur("SUPPORT_POLL_INTERVAL", supportDefaultPoll); err != nil {
		return SupportConfig{}, err
	}
	if cfg.PollInterval < supportMinPoll {
		return SupportConfig{}, fmt.Errorf("SUPPORT_POLL_INTERVAL %s must be at least %s", cfg.PollInterval, supportMinPoll)
	}
	if cfg.RequestTimeout, err = dur("SUPPORT_REQUEST_TIMEOUT", supportDefaultReqTO); err != nil {
		return SupportConfig{}, err
	}
	if cfg.RequestTimeout < supportMinReqTO || cfg.RequestTimeout > cfg.Wait {
		return SupportConfig{}, fmt.Errorf("SUPPORT_REQUEST_TIMEOUT %s must be between %s and SUPPORT_ASK_WAIT (%s)",
			cfg.RequestTimeout, supportMinReqTO, cfg.Wait)
	}
	if cfg.TokenTTL, err = dur("SUPPORT_TOKEN_TTL", supportDefaultTokenTTL); err != nil {
		return SupportConfig{}, err
	}
	if cfg.TokenTTL < supportMinTokenTTL || cfg.TokenTTL > supportMaxTokenTTL {
		return SupportConfig{}, fmt.Errorf("SUPPORT_TOKEN_TTL %s must be between %s and %s", cfg.TokenTTL, supportMinTokenTTL, supportMaxTokenTTL)
	}
	return cfg, nil
}

func isLoopbackHost(h string) bool {
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// supportHTTPClient never follows a redirect (the bearer must not leave the
// configured host) and has no Client.Timeout: every request takes its
// deadline from its context.
var supportHTTPClient = &http.Client{
	Transport: tracingTransport{base: http.DefaultTransport},
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// --- A2A 1.0 types (the subset this adapter reads) ---

type a2aPart struct {
	Text      *string         `json:"text,omitempty"`
	Raw       json.RawMessage `json:"raw,omitempty"`
	URL       *string         `json:"url,omitempty"`
	Data      json.RawMessage `json:"data,omitempty"`
	MediaType string          `json:"mediaType,omitempty"`
	Filename  string          `json:"filename,omitempty"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
}

type a2aMessage struct {
	MessageID string          `json:"messageId"`
	Role      string          `json:"role"`
	ContextID string          `json:"contextId,omitempty"`
	TaskID    string          `json:"taskId,omitempty"`
	Parts     []a2aPart       `json:"parts"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
}

type a2aArtifact struct {
	ArtifactID string    `json:"artifactId"`
	Name       string    `json:"name,omitempty"`
	Parts      []a2aPart `json:"parts"`
}

type a2aStatus struct {
	State     string      `json:"state"`
	Message   *a2aMessage `json:"message,omitempty"`
	Timestamp string      `json:"timestamp,omitempty"`
}

type a2aTask struct {
	ID        string          `json:"id"`
	ContextID string          `json:"contextId,omitempty"`
	Status    a2aStatus       `json:"status"`
	Artifacts []a2aArtifact   `json:"artifacts,omitempty"`
	History   []a2aMessage    `json:"history,omitempty"` // decoded only so it can be proven ignored
	Metadata  json.RawMessage `json:"metadata,omitempty"`
}

// normalizeState strips an optional TASK_STATE_ prefix and uppercases.
func normalizeState(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	return strings.TrimPrefix(s, "TASK_STATE_")
}

func isTerminalState(s string) bool {
	switch s {
	case "COMPLETED", "FAILED", "CANCELED", "REJECTED":
		return true
	}
	return false
}

func isInterruptedState(s string) bool { return s == "INPUT_REQUIRED" || s == "AUTH_REQUIRED" }

// --- transport ---

// supportError is a failed call to mctl-support. status is 0 for transport
// and decode failures.
type supportError struct {
	status int
	msg    string
}

func (e *supportError) Error() string { return e.msg }

func (e *supportError) refusal() bool { return e.status >= 300 && e.status < 500 }

// supportDo performs one request. wrapped selects the message:send reply
// shape ({"task"} or {"message"}); otherwise the body is a bare Task. Every
// failure is an error; a zero answer is never returned in its place.
func (s *Server) supportDo(ctx context.Context, cfg *SupportConfig, bearer, method, path string, body any, wrapped bool) (*a2aTask, *a2aMessage, error) {
	if bearer == "" {
		return nil, nil, &supportError{msg: "support_token_unavailable: no support token to send to mctl-support"}
	}
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, nil, &supportError{msg: "could not encode request: " + err.Error()}
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, cfg.BaseURL+path, rdr)
	if err != nil {
		return nil, nil, &supportError{msg: "could not build request: " + err.Error()}
	}
	req.Header.Set("A2A-Version", supportA2AVersion)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := supportHTTPClient.Do(req)
	if err != nil {
		slog.Warn("mctl-support request failed", "method", method, "error", err)
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, nil, &supportError{msg: "mctl-support request timed out"}
		}
		return nil, nil, &supportError{msg: "mctl-support transport error: " + err.Error()}
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, supportMaxBody))
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, nil, &supportError{msg: "mctl-support request timed out"}
		}
		return nil, nil, &supportError{msg: "mctl-support transport error reading the reply: " + err.Error()}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		slog.Warn("mctl-support answered non-2xx", "method", method, "status", resp.StatusCode)
		detail := shortBody(raw)
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			detail = "redirects are not followed"
		}
		return nil, nil, &supportError{status: resp.StatusCode,
			msg: fmt.Sprintf("mctl-support returned %d: %s", resp.StatusCode, detail)}
	}
	decodeErr := func(why string) error {
		return &supportError{msg: "mctl-support response could not be decoded: " + why}
	}
	if !wrapped {
		var t a2aTask
		if err := json.Unmarshal(raw, &t); err != nil {
			return nil, nil, decodeErr(err.Error())
		}
		if t.ID == "" || t.Status.State == "" {
			return nil, nil, decodeErr("not an A2A task")
		}
		return &t, nil, nil
	}
	var env struct {
		Task    *a2aTask    `json:"task"`
		Message *a2aMessage `json:"message"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, nil, decodeErr(err.Error())
	}
	switch {
	case env.Task != nil && env.Message == nil && env.Task.ID != "" && env.Task.Status.State != "":
		return env.Task, nil, nil
	case env.Message != nil && env.Task == nil:
		return nil, env.Message, nil
	}
	return nil, nil, decodeErr("neither a task nor a message")
}

func shortBody(b []byte) string {
	s := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, strings.TrimSpace(string(b)))
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	if s == "" {
		return "(empty body)"
	}
	return s
}

// --- answer rendering ---

type supportAnswer struct {
	TaskID         string            `json:"task_id,omitempty"`
	ContextID      string            `json:"context_id,omitempty"`
	State          string            `json:"state,omitempty"`
	Terminal       bool              `json:"terminal"`
	AnswerSource   string            `json:"answer_source,omitempty"`
	Text           string            `json:"text,omitempty"`
	Result         json.RawMessage   `json:"result,omitempty"`
	AdditionalData []json.RawMessage `json:"additional_data,omitempty"`
	Reason         string            `json:"reason,omitempty"`
	Note           string            `json:"note,omitempty"`
}

// errSupportEmptyAnswer marks a COMPLETED task with no meaningful answer.
var errSupportEmptyAnswer = errors.New("support_empty_answer")

func isJSONObject(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	return len(t) > 0 && t[0] == '{'
}

func isTextPart(p a2aPart) bool { return p.Text != nil && strings.TrimSpace(*p.Text) != "" }

func meaningful(parts []a2aPart) bool {
	for _, p := range parts {
		if isTextPart(p) || isJSONObject(p.Data) {
			return true
		}
	}
	return false
}

// renderParts applies the answer rule to one chosen source: the non-blank
// text parts verbatim joined with "\n", the first object data part as the
// result, further object data parts as additional_data.
func renderParts(parts []a2aPart) (text string, result json.RawMessage, more []json.RawMessage) {
	var texts []string
	for _, p := range parts {
		switch {
		case isTextPart(p):
			texts = append(texts, *p.Text)
		case isJSONObject(p.Data):
			if result == nil {
				result = append(json.RawMessage(nil), p.Data...)
			} else {
				more = append(more, append(json.RawMessage(nil), p.Data...))
			}
		}
	}
	return strings.Join(texts, "\n"), result, more
}

// renderSupportAnswer renders a task or a direct message. For a COMPLETED
// task the answer is status.message first, artifacts only when status.message
// is not meaningful, never both, and history never. COMPLETED with no
// meaningful source is an error wrapping errSupportEmptyAnswer.
func renderSupportAnswer(task *a2aTask, msg *a2aMessage) (supportAnswer, error) {
	if task == nil {
		if msg == nil || !meaningful(msg.Parts) {
			return supportAnswer{}, fmt.Errorf("%w: mctl-support replied with a message that carries no answer", errSupportEmptyAnswer)
		}
		a := supportAnswer{ContextID: msg.ContextID, Terminal: true, AnswerSource: "message"}
		a.Text, a.Result, a.AdditionalData = renderParts(msg.Parts)
		return a, nil
	}
	state := normalizeState(task.Status.State)
	a := supportAnswer{TaskID: task.ID, ContextID: task.ContextID, State: state, Terminal: isTerminalState(state)}
	var statusParts []a2aPart
	if task.Status.Message != nil {
		statusParts = task.Status.Message.Parts
	}
	switch {
	case state == "COMPLETED":
		var chosen []a2aPart
		switch {
		case meaningful(statusParts):
			a.AnswerSource, chosen = "status_message", statusParts
		default:
			var art []a2aPart
			for _, x := range task.Artifacts {
				art = append(art, x.Parts...)
			}
			if !meaningful(art) {
				return a, fmt.Errorf("%w: task %s is COMPLETED but carries no answer in status.message or artifacts", errSupportEmptyAnswer, task.ID)
			}
			a.AnswerSource, chosen = "artifacts", art
		}
		a.Text, a.Result, a.AdditionalData = renderParts(chosen)
	case isTerminalState(state) || isInterruptedState(state):
		a.Reason, _, _ = renderParts(statusParts)
	}
	return a, nil
}

func supportResultJSON(a supportAnswer, isErr bool) *mcplib.CallToolResult {
	b, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return mcplib.NewToolResultError("could not encode the support answer: " + err.Error())
	}
	if isErr {
		return mcplib.NewToolResultError(string(b))
	}
	return mcplib.NewToolResultText(string(b))
}

// supportOutcome turns a rendered task into the tool result: FAILED, REJECTED
// and CANCELED are tool errors carrying state and reason; everything else
// rendered is a normal result.
func supportOutcome(task *a2aTask, msg *a2aMessage) *mcplib.CallToolResult {
	a, err := renderSupportAnswer(task, msg)
	if err != nil {
		return mcplib.NewToolResultError(err.Error())
	}
	switch a.State {
	case "FAILED", "REJECTED", "CANCELED":
		return supportResultJSON(a, true)
	}
	return supportResultJSON(a, false)
}

// --- support token mint ---

// SupportTokenMinter mints a support-audience access token for a caller.
type SupportTokenMinter interface {
	IssueSupportToken(u *auth.User, ttl time.Duration) (auth.SupportToken, error)
}

// SupportTokenMintRecord is what the auditor learns about one mint. It never
// carries the token.
type SupportTokenMintRecord struct {
	Tool      string
	Tenant    string
	JTI       string
	Audience  string
	ExpiresAt time.Time
}

// SupportTokenAuditor records one support-token mint.
type SupportTokenAuditor interface {
	AuditSupportTokenMint(ctx context.Context, rec SupportTokenMintRecord)
}

// SetSupportTokenMinter wires the minter; without one the support tools fail
// closed (stdio mode).
func (s *Server) SetSupportTokenMinter(m SupportTokenMinter) { s.supportMinter.Store(&m) }

// SetSupportTokenAuditor wires the mint auditor.
func (s *Server) SetSupportTokenAuditor(a SupportTokenAuditor) { s.supportAuditor.Store(&a) }

const supportTokenUnavailable = "support_token_unavailable: this server cannot mint a support-audience token"

func (s *Server) supportMintDeps() (SupportTokenMinter, SupportTokenAuditor) {
	var m SupportTokenMinter
	var a SupportTokenAuditor
	if p := s.supportMinter.Load(); p != nil {
		m = *p
	}
	if p := s.supportAuditor.Load(); p != nil {
		a = *p
	}
	return m, a
}

// supportMintPrecheck fails before any other work when no token can be
// minted: no minter or auditor is wired (stdio), or no user is in the
// context, whom mintSupportBearer would refuse anyway.
func (s *Server) supportMintPrecheck(ctx context.Context) *mcplib.CallToolResult {
	m, a := s.supportMintDeps()
	if m == nil || a == nil || auth.UserFromContext(ctx) == nil {
		return mcplib.NewToolResultError(supportTokenUnavailable)
	}
	return nil
}

// mintSupportBearer mints the one token a tool call sends to mctl-support and
// audits the mint. Errors never contain a token.
func (s *Server) mintSupportBearer(ctx context.Context, tool, tenant string, ttl time.Duration) (string, *mcplib.CallToolResult) {
	m, a := s.supportMintDeps()
	u := auth.UserFromContext(ctx)
	if m == nil || a == nil || u == nil {
		return "", mcplib.NewToolResultError(supportTokenUnavailable)
	}
	tok, err := m.IssueSupportToken(u, ttl)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrSupportResourceDisabled):
			return "", mcplib.NewToolResultError("support_audience_not_configured: OAUTH_SUPPORT_RESOURCE is empty; the caller's token is never forwarded instead")
		case errors.Is(err, auth.ErrSupportTokenRefused):
			return "", mcplib.NewToolResultError("support_token_refused: this caller may not be given a support token")
		}
		slog.Warn("support token mint failed", "tool", tool, "error", err)
		return "", mcplib.NewToolResultError("support_token_unavailable: the support token could not be minted")
	}
	a.AuditSupportTokenMint(ctx, SupportTokenMintRecord{
		Tool: tool, Tenant: tenant, JTI: tok.JTI, Audience: tok.Audience, ExpiresAt: tok.ExpiresAt,
	})
	return tok.Token, nil
}

// --- tenant check ---

// supportTenantAllowed reports whether the caller in the context may act on
// tenant (HasTenantAccess). supportMintPrecheck has already refused a call
// with no user, so a missing one here is an error, never "allowed".
func (s *Server) supportTenantAllowed(ctx context.Context, tenant string) (bool, error) {
	u := auth.UserFromContext(ctx)
	if u == nil {
		return false, errors.New("no caller identity")
	}
	return u.HasTenantAccess(tenant), nil
}

// --- tools ---

const supportNotConfigured = "the support agent is not configured on this server"

func (s *Server) toolAskSupport() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_ask_support",
		mcplib.WithTitleAnnotation("Ask the support agent"),
		mcplib.WithReadOnlyHintAnnotation(false),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithIdempotentHintAnnotation(false),
		mcplib.WithDescription(`Ask the tenant support agent a question about your tenant. It creates a support task, spends the tenant's model budget, and waits up to the configured bound for the answer (default 60s). If the answer is not ready in time the result carries the task id: continue with mctl_get_support_task. mctl-api sends the support agent a short-lived token for your principal, valid only for the support agent; you must be a member of the tenant.`),
		commerceTenantArg,
		mcplib.WithString("question", mcplib.Required(), mcplib.Description("The question for the support agent.")),
		mcplib.WithString("context_id", mcplib.Description("Continue an earlier conversation: the context_id of a previous answer.")),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		cfg := s.support.Load()
		if cfg == nil || cfg.BaseURL == "" {
			return mcplib.NewToolResultError(supportNotConfigured), nil
		}
		tenant, errResult := normalizeTenantArg(req)
		if errResult != nil {
			return errResult, nil
		}
		question, errResult := strictStringArg(req, "question")
		if errResult != nil {
			return errResult, nil
		}
		if strings.TrimSpace(question) == "" {
			return mcplib.NewToolResultError("missing required argument: question"), nil
		}
		if len(question) > supportMaxQuestion {
			return mcplib.NewToolResultError(fmt.Sprintf("question must be at most %d bytes", supportMaxQuestion)), nil
		}
		contextID, errResult := strictStringArg(req, "context_id")
		if errResult != nil {
			return errResult, nil
		}
		if errResult := s.supportMintPrecheck(ctx); errResult != nil {
			return errResult, nil
		}
		allowed, err := s.supportTenantAllowed(ctx, tenant)
		if err != nil {
			slog.Warn("support tenant membership could not be determined", "error", err)
			return mcplib.NewToolResultError("could not determine your membership of tenant " + tenant + ": " + err.Error()), nil
		}
		if !allowed {
			return mcplib.NewToolResultError("tenant_forbidden: you are not a member of tenant " + tenant), nil
		}

		bearer, errResult := s.mintSupportBearer(ctx, "mctl_ask_support", tenant, cfg.TokenTTL)
		if errResult != nil {
			return errResult, nil
		}

		messageID := uuid.NewString()
		msg := map[string]any{
			"messageId": messageID,
			"role":      "ROLE_USER",
			"parts":     []map[string]any{{"text": question}},
		}
		if contextID != "" {
			msg["contextId"] = contextID
		}
		body := map[string]any{
			"message":       msg,
			"configuration": map[string]any{"returnImmediately": true},
			"metadata":      map[string]any{"tenant": tenant},
		}

		// One budget for the send and all polling; never reset or extended.
		budgetCtx, cancel := context.WithDeadline(ctx, time.Now().Add(cfg.Wait))
		defer cancel()

		task, reply, err := s.supportDo(budgetCtx, cfg, bearer, http.MethodPost, "/message:send", body, true)
		if err != nil {
			var se *supportError
			if errors.As(err, &se) && se.refusal() {
				return mcplib.NewToolResultError(err.Error()), nil
			}
			if errors.Is(ctx.Err(), context.Canceled) {
				return nil, ctx.Err()
			}
			return mcplib.NewToolResultError(fmt.Sprintf("support_send_outcome_unknown: message %s may or may not have created a task (%s); the call was not retried, and a task may exist and may spend budget", messageID, err.Error())), nil
		}
		if reply != nil {
			return supportOutcome(nil, reply), nil
		}
		return s.supportAwait(ctx, budgetCtx, cfg, bearer, task)
	}
	return tool, handler
}

// supportAwait polls task until it is terminal or interrupted, or budgetCtx
// ends. A client cancellation of ctx is returned as an error; a deadline
// (the budget's or the request's) ends the wait like the budget does.
func (s *Server) supportAwait(ctx, budgetCtx context.Context, cfg *SupportConfig, bearer string, task *a2aTask) (*mcplib.CallToolResult, error) {
	state := normalizeState(task.Status.State)
	if isTerminalState(state) || isInterruptedState(state) {
		return supportOutcome(task, nil), nil
	}
	id := task.ID
	last := task
	polled := false
	var lastErr error
	path := "/tasks/" + url.PathEscape(id)
	for {
		timer := time.NewTimer(cfg.PollInterval)
		select {
		case <-budgetCtx.Done():
			timer.Stop()
		case <-timer.C:
			pctx, pcancel := context.WithTimeout(budgetCtx, cfg.RequestTimeout)
			t, _, err := s.supportDo(pctx, cfg, bearer, http.MethodGet, path, nil, false)
			pcancel()
			if err == nil {
				last, polled, lastErr = t, true, nil
				st := normalizeState(t.Status.State)
				if isTerminalState(st) || isInterruptedState(st) {
					return supportOutcome(t, nil), nil
				}
				continue
			}
			var se *supportError
			if errors.As(err, &se) && se.refusal() && se.status != http.StatusTooManyRequests {
				return mcplib.NewToolResultError(fmt.Sprintf("task %s: polling stopped: %s", id, err.Error())), nil
			}
			if budgetCtx.Err() != nil {
				// The budget, not mctl-support, cut this poll short: it says
				// nothing about the last completed read.
				if !polled {
					lastErr = err
				}
				break
			}
			lastErr = err
			continue
		}
		break
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return nil, ctx.Err()
	}
	if lastErr != nil {
		return mcplib.NewToolResultError(fmt.Sprintf("task %s is not finished and could not be read (%s); continue with mctl_get_support_task", id, lastErr.Error())), nil
	}
	// No poll attempted (the send used the whole budget): the send reply is
	// the last successful read, so this is an unfinished task, not an error.
	return supportResultJSON(supportAnswer{
		TaskID:    id,
		ContextID: last.ContextID,
		State:     normalizeState(last.Status.State),
		Terminal:  false,
		Note:      "still running; call mctl_get_support_task with this task_id",
	}, false), nil
}

func (s *Server) toolGetSupportTask() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_get_support_task",
		mcplib.WithTitleAnnotation("Get a support task"),
		mcplib.WithReadOnlyHintAnnotation(true),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithDescription(`Read one support agent task by id: its state and, once completed, the answer. Use it to collect an answer that mctl_ask_support did not wait for. mctl-api sends the support agent a short-lived token for your principal, valid only for the support agent; the support agent decides what you may see.`),
		mcplib.WithString("id", mcplib.Required(), mcplib.Description("The task_id returned by mctl_ask_support.")),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		cfg := s.support.Load()
		if cfg == nil || cfg.BaseURL == "" {
			return mcplib.NewToolResultError(supportNotConfigured), nil
		}
		raw, errResult := strictStringArg(req, "id")
		if errResult != nil {
			return errResult, nil
		}
		id := strings.TrimSpace(raw)
		switch {
		case id == "":
			return mcplib.NewToolResultError("missing required argument: id"), nil
		case len(id) > supportMaxTaskID:
			return mcplib.NewToolResultError(fmt.Sprintf("id must be at most %d bytes", supportMaxTaskID)), nil
		case id == "." || id == ".." || strings.ContainsAny(id, `/\?#`) || strings.IndexFunc(id, unicode.IsControl) >= 0:
			return mcplib.NewToolResultError("id must be one path segment"), nil
		}
		readTTL := cfg.RequestTimeout + 60*time.Second
		if readTTL > supportReadTokenCap {
			readTTL = supportReadTokenCap
		}
		bearer, errResult := s.mintSupportBearer(ctx, "mctl_get_support_task", "", readTTL)
		if errResult != nil {
			return errResult, nil
		}
		rctx, cancel := context.WithTimeout(ctx, cfg.RequestTimeout)
		defer cancel()
		task, _, err := s.supportDo(rctx, cfg, bearer, http.MethodGet, "/tasks/"+url.PathEscape(id), nil, false)
		if err != nil {
			if errors.Is(ctx.Err(), context.Canceled) {
				return nil, ctx.Err()
			}
			return mcplib.NewToolResultError(fmt.Sprintf("task %s: %s", id, err.Error())), nil
		}
		return supportOutcome(task, nil), nil
	}
	return tool, handler
}
