package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/k8s"
)

type fakeBinder struct {
	binding *k8s.AgentRunBinding
	err     error
	tokens  []string
}

func (f *fakeBinder) Bind(_ context.Context, token string) (*k8s.AgentRunBinding, error) {
	f.tokens = append(f.tokens, token)
	return f.binding, f.err
}

// exchangeEnv is a work-items env with the exchange and self-revoke routes,
// and a running execution the fake binder binds to.
func exchangeEnv(t *testing.T) (*workItemsEnv, *fakeBinder, string) {
	e := newWorkItemsEnv(t)
	item := e.open(auth.NewServiceUser(), nil)
	execID := e.attachExecution(auth.NewServiceUser(), item["id"].(string), "run-x", "Running")
	b := &fakeBinder{binding: &k8s.AgentRunBinding{
		Agent: "issue-investigator", Scope: auth.AgentScopeInvestigate, ExecutionID: execID,
		Namespace: "argo-workflows", ServiceAccount: "mctl-agents-runner",
		Pod: "inv-1-pod", Workflow: "inv-1", Template: "mctl-agents-investigate",
		Deadline: time.Now().Add(30 * time.Minute),
	}}
	e.h.opts.AgentRunBinder = b
	e.router.Post("/api/v1/agent-run-tokens/exchange", e.h.ExchangeAgentRunToken)
	e.router.With(e.h.agentScopeGate).Post("/api/v1"+agentRunTokenSelfRevokeRoute, e.h.RevokeOwnAgentRunToken)
	return e, b, execID
}

func (e *workItemsEnv) exchange(bearer string, body any) wiResponse {
	e.t.Helper()
	return e.do(nil, "POST", "/api/v1/agent-run-tokens/exchange", body, "Authorization", "Bearer "+bearer)
}

func TestExchangeAgentRunToken_MintsTheBoundRunsScopedToken(t *testing.T) {
	e, b, execID := exchangeEnv(t)
	// The body is not the pod's to fill: whatever it asks for, the binding
	// decides.
	res := e.exchange("sa-token", map[string]any{"agent": "implementer", "scope": "", "ttl_seconds": 86400})
	if res.code != http.StatusCreated {
		t.Fatalf("exchange = %d %s", res.code, res.raw)
	}
	if len(b.tokens) != 1 || b.tokens[0] != "sa-token" {
		t.Errorf("binder saw %v, want the bearer", b.tokens)
	}
	if res.body["agent"] != "issue-investigator" || res.body["scope"] != auth.AgentScopeInvestigate || res.body["execution_id"] != execID {
		t.Errorf("exchanged token = %v", res.body)
	}
	// Never past the run's own deadline.
	exp, err := time.Parse(time.RFC3339Nano, res.body["expires_at"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if exp.After(b.binding.Deadline) {
		t.Errorf("expires_at %v is past the run's deadline %v", exp, b.binding.Deadline)
	}

	// The token authenticates as the scoped run.
	token := res.body["token"].(string)
	run, err := e.h.opts.WorkItems.ResolveAgentRunToken(context.Background(), token)
	if err != nil {
		t.Fatalf("resolve exchanged token: %v", err)
	}
	if run.Scope != auth.AgentScopeInvestigate || run.Agent != "issue-investigator" || run.ExecutionID != execID {
		t.Errorf("resolved run = %+v", run)
	}

	found := false
	for _, entry := range e.audit.List(1000) {
		if entry.Operation != "agent_run_token.exchange" {
			continue
		}
		found = true
		if entry.Parameters["pod"] != "inv-1-pod" || entry.Parameters["workflow"] != "inv-1" ||
			entry.UserID != "k8s:system:serviceaccount:argo-workflows:mctl-agents-runner" {
			t.Errorf("exchange audit row = %+v", entry)
		}
		for k, v := range entry.Parameters {
			if strings.Contains(v, token) {
				t.Fatalf("plaintext token in audit field %s", k)
			}
		}
	}
	if !found {
		t.Error("no agent_run_token.exchange audit row")
	}
}

func TestExchangeAgentRunToken_CapsAtTwoHoursWithoutADeadline(t *testing.T) {
	e, b, _ := exchangeEnv(t)
	b.binding.Deadline = time.Time{}
	res := e.exchange("sa-token", nil)
	if res.code != http.StatusCreated {
		t.Fatalf("exchange = %d %s", res.code, res.raw)
	}
	exp, _ := time.Parse(time.RFC3339Nano, res.body["expires_at"].(string))
	if exp.After(time.Now().Add(MaxExchangedAgentRunTokenTTL + time.Minute)) {
		t.Errorf("expires_at %v exceeds the %v cap", exp, MaxExchangedAgentRunTokenTTL)
	}
}

func TestExchangeAgentRunToken_IssuesNothingUnlessBound(t *testing.T) {
	for _, c := range []struct {
		name   string
		setup  func(*workItemsEnv, *fakeBinder)
		bearer string
		want   int
		code   string
	}{
		{"no bearer", func(*workItemsEnv, *fakeBinder) {}, "", http.StatusUnauthorized, ""},
		{"token not authenticated", func(_ *workItemsEnv, b *fakeBinder) {
			b.binding, b.err = nil, &k8s.BindingRefusedError{Reason: "token_not_authenticated", Unauthenticated: true}
		}, "sa", http.StatusUnauthorized, artCodeExchangeRefused},
		{"pod does not bind", func(_ *workItemsEnv, b *fakeBinder) {
			b.binding, b.err = nil, &k8s.BindingRefusedError{Reason: "workflow_template_not_allowed"}
		}, "sa", http.StatusForbidden, artCodeExchangeRefused},
		{"cluster unreadable", func(_ *workItemsEnv, b *fakeBinder) {
			b.binding, b.err = nil, errors.New("connection refused")
		}, "sa", http.StatusServiceUnavailable, artCodeExchangeUnavailable},
		{"exchange off", func(e *workItemsEnv, _ *fakeBinder) { e.h.opts.AgentRunBinder = nil }, "sa", http.StatusServiceUnavailable, artCodeExchangeUnavailable},
		{"deadline passed", func(_ *workItemsEnv, b *fakeBinder) {
			b.binding.Deadline = time.Now().Add(20 * time.Second)
		}, "sa", http.StatusForbidden, artCodeRunEnded},
		{"execution ended", func(e *workItemsEnv, b *fakeBinder) {
			item := e.open(auth.NewServiceUser(), nil)
			b.binding.ExecutionID = e.attachExecution(auth.NewServiceUser(), item["id"].(string), "run-done", "Succeeded")
		}, "sa", http.StatusConflict, artCodeExecutionTerminal},
	} {
		t.Run(c.name, func(t *testing.T) {
			e, b, _ := exchangeEnv(t)
			c.setup(e, b)
			res := e.exchange(c.bearer, nil)
			if res.code != c.want {
				t.Fatalf("exchange = %d %s, want %d", res.code, res.raw, c.want)
			}
			if _, ok := res.body["token"]; ok {
				t.Fatal("a refused exchange returned a token")
			}
			if c.code != "" && code(res) != c.code {
				t.Errorf("code = %q, want %q", code(res), c.code)
			}
		})
	}
}

func TestRevokeOwnAgentRunToken(t *testing.T) {
	e, _, _ := exchangeEnv(t)
	res := e.exchange("sa-token", nil)
	if res.code != http.StatusCreated {
		t.Fatalf("exchange = %d %s", res.code, res.raw)
	}
	token := res.body["token"].(string)
	run, err := e.h.opts.WorkItems.ResolveAgentRunToken(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	// A scoped run reaches its own revoke whatever its scope lists.
	rev := e.do(auth.NewAgentUser(run.Agent, *run), "POST", "/api/v1"+agentRunTokenSelfRevokeRoute, nil)
	if rev.code != http.StatusNoContent {
		t.Fatalf("self revoke = %d %s", rev.code, rev.raw)
	}
	if _, err := e.h.opts.WorkItems.ResolveAgentRunToken(context.Background(), token); !errors.Is(err, auth.ErrAgentRunNotFound) {
		t.Fatalf("revoked token still resolves: %v", err)
	}

	// Anyone else has no run token to revoke.
	if rev := e.do(auth.NewServiceUser(), "POST", "/api/v1"+agentRunTokenSelfRevokeRoute, nil); rev.code != http.StatusBadRequest {
		t.Errorf("service self revoke = %d, want 400", rev.code)
	}
}
