package api

// Human-input read model (mctl-api#261). A DevLoop investigator that needs a
// human decision seals ONE HumanInputRequest into mctl-gitops and its
// DevLoopWorkflow parks in WAITING_FOR_INPUT (mctl-agents ADR 013). These
// handlers let a surface (Telegram, Portal) find and render such requests
// without talking to Temporal directly.
//
// Two sources, each authoritative for one thing:
//   - the request CONTENT comes from gitops and is verified against its seal
//     (humaninput.ParseRequest recomputes request_hash), so what a human is
//     shown is exactly what the investigator asked;
//   - whether it is still PENDING comes from the owning workflow's
//     human_input_state query. mctl-api keeps no copy of that state machine:
//     an answered request stays in gitops, and only the workflow knows it
//     was answered.
//
// Question and reason are shown only to someone who may answer (their
// GitHub-verified "github:<login>" is in the request's actor_refs), to
// admins, and to the service principal that relays for a surface. Everyone
// else does not learn the request exists.

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/humaninput"
	"github.com/mctlhq/mctl-api/internal/temporalclient"
)

// humanInputQueryTimeout bounds each human_input_state query. Temporal
// blocks a query until a worker answers, so during a worker outage the only
// other bound would be the 30s API timeout.
const humanInputQueryTimeout = 3 * time.Second

// humanInputListBudget bounds all state queries of one list call together,
// well inside the 30s request timeout, so a Temporal worker outage yields a
// bounded answer instead of a per-request pile-up.
var humanInputListBudget = 10 * time.Second

// Read-model states. "pending" is the only one a response can be accepted
// in; everything else is either terminal for this request or unknown.
const (
	HumanInputPending    = "pending"
	HumanInputExpired    = "expired"
	HumanInputTimedOut   = "timed_out"
	HumanInputResolved   = "resolved"
	HumanInputNotPending = "not_pending"
	HumanInputUnknown    = "unknown"
)

var humanInputIDPattern = regexp.MustCompile(`^hir-[0-9a-f]{16}$`)

// humanInputNow is the clock expiry is judged against; tests replace it.
var humanInputNow = time.Now

// humanInputView is the redacted read model: what a surface needs to render
// the request and nothing else. Execution hashes, the target commit, Argo
// names and question_hash are internal correlation data and are omitted.
type humanInputView struct {
	RequestID      string   `json:"request_id"`
	RequestHash    string   `json:"request_hash"`
	RequestVersion int      `json:"request_version"`
	Round          int      `json:"round"`
	WorkItemID     string   `json:"work_item_id"`
	Service        string   `json:"service"`
	Proposal       string   `json:"proposal"`
	WorkflowID     string   `json:"workflow_id"`
	Agent          string   `json:"agent"`
	Question       string   `json:"question"`
	Reason         string   `json:"reason"`
	ResponseType   string   `json:"response_type"`
	Options        []string `json:"options,omitempty"`
	ContextRefs    []string `json:"context_refs"`
	Audience       string   `json:"audience"`
	// EligibleActors is the full allow-list; only admins and the service
	// principal see it. Everyone else sees only CanRespond for themselves.
	EligibleActors []string `json:"eligible_actors,omitempty"`
	CanRespond     bool     `json:"can_respond"`
	CreatedAt      string   `json:"created_at"`
	ExpiresAt      string   `json:"expires_at"`
	State          string   `json:"state"`
	StateDetail    string   `json:"state_detail,omitempty"`
}

type sealedHumanInput struct {
	file gitopsHumanInputFile
	req  *humaninput.Request
}

// gitopsHumanInputFile carries where a request was found.
type gitopsHumanInputFile struct{ Service, Proposal string }

// callerActorRef is the respondent reference an authenticated caller answers
// as: "github:<login>", the form mctl-agents writes into actor_refs, and
// only when authentication PROVED a GitHub login (GitHub token, or the local
// OAuth JWT minted after the GitHub callback). A Dex username that happens
// to equal someone's GitHub login is not that person, so a caller without a
// verified login has no reference and is never eligible.
func callerActorRef(u *auth.User) (string, bool) {
	login, ok := u.GitHubLogin()
	if !ok {
		return "", false
	}
	return "github:" + login, true
}

// callerCanRespond: the caller's verified reference is in actor_refs.
func callerCanRespond(u *auth.User, req *humaninput.Request) bool {
	ref, ok := callerActorRef(u)
	return ok && req.CanRespond(ref)
}

// canSeeHumanInput: a potential respondent, an admin, or the service
// principal relaying for a surface.
func canSeeHumanInput(u *auth.User, req *humaninput.Request) bool {
	return u.IsAdmin() || u.IsService() || callerCanRespond(u, req)
}

// loadHumanInputRequests reads and verifies every sealed request in gitops.
// A document that fails verification is skipped with a warning: it was
// malformed or altered after sealing, and the workflow rejects it too.
func (h *Handlers) loadHumanInputRequests() ([]sealedHumanInput, error) {
	files, err := h.opts.GitReader.ListHumanInputRequests()
	if err != nil {
		return nil, err
	}
	out := make([]sealedHumanInput, 0, len(files))
	for _, f := range files {
		req, err := humaninput.ParseRequest(f.Raw)
		if err != nil {
			slog.Warn("human_input.invalid_document", "service", f.Service, "proposal", f.Proposal, "error", err)
			continue
		}
		out = append(out, sealedHumanInput{file: gitopsHumanInputFile{Service: f.Service, Proposal: f.Proposal}, req: req})
	}
	return out, nil
}

// humanInputStates resolves request states for one HTTP call, querying each
// owning workflow execution at most once: the query answers for the
// workflow (which request it waits on), so every request of that execution
// shares the result.
type humanInputStates struct {
	client DevLoopClient
	cache  map[string]humanInputQueryResult
}

type humanInputQueryResult struct {
	st  *temporalclient.HumanInputState
	err error
}

func (h *Handlers) newHumanInputStates() *humanInputStates {
	return &humanInputStates{client: h.opts.TemporalClient, cache: map[string]humanInputQueryResult{}}
}

func requestRunID(req *humaninput.Request) string {
	if req.Execution.TemporalRunID != nil {
		return *req.Execution.TemporalRunID
	}
	return ""
}

// state asks the owning workflow whether it is waiting on req.
func (q *humanInputStates) state(ctx context.Context, req *humaninput.Request, now time.Time) (state, detail string) {
	if q.client == nil {
		return HumanInputUnknown, "dev-loop Temporal client not configured"
	}
	wf, runID := req.Execution.TemporalWorkflowID, requestRunID(req)
	key := wf + "@" + runID
	res, ok := q.cache[key]
	if !ok {
		qctx, cancel := context.WithTimeout(ctx, humanInputQueryTimeout)
		res.st, res.err = q.client.QueryHumanInputState(qctx, wf, runID)
		cancel()
		q.cache[key] = res
	}
	if res.err != nil {
		if temporalclient.IsNotFound(res.err) {
			// No such execution (never started, or past retention): it is
			// certainly not waiting on anything.
			return HumanInputNotPending, "owning workflow not found"
		}
		slog.Debug("human_input_state query failed", "workflow_id", wf, "error", res.err)
		return HumanInputUnknown, "owning workflow did not answer"
	}
	if res.st == nil {
		return HumanInputUnknown, "owning workflow returned no state"
	}
	return deriveHumanInputState(res.st, req, now)
}

// resolve is the state of req for one call.
//
// Past expires_at a request can never be pending, whatever the workflow
// says. When only "pending or not" matters (terminal=false) that settles it
// without a query. Otherwise the workflow still decides the terminal state
// (an answered request is resolved, not expired; a timed-out one is
// timed_out), and expires_at is the fallback only when the workflow cannot
// say: a missing or failing Temporal client never turns an expired request
// into "unknown".
func (q *humanInputStates) resolve(ctx context.Context, req *humaninput.Request, now time.Time, terminal bool) (state, detail string) {
	expired := !now.Before(req.Expires())
	if expired && !terminal {
		return HumanInputExpired, ""
	}
	state, detail = q.state(ctx, req, now)
	if expired && state == HumanInputUnknown {
		return HumanInputExpired, ""
	}
	return state, detail
}

// deriveHumanInputState maps the workflow's own state onto this request.
//
// A workflow that was terminated or failed while parked still answers the
// query with its last state, so such a request reads as pending until
// expires_at. Telling it apart needs a describe call per execution; a
// response to it is refused anyway, because signalling a closed execution
// fails and the response endpoint then reports it not pending.
func deriveHumanInputState(st *temporalclient.HumanInputState, req *humaninput.Request, now time.Time) (string, string) {
	if st.RequestID != req.RequestID {
		if st.RequestID == "" {
			return HumanInputNotPending, "the workflow is not waiting on this request"
		}
		return HumanInputNotPending, "the workflow has moved on to another request"
	}
	switch st.State {
	case temporalclient.HumanInputWaitingForInput:
		// The workflow accepts nothing at or after expires_at
		// (validate_response), even while it is still parked.
		if !now.Before(req.Expires()) {
			return HumanInputExpired, ""
		}
		return HumanInputPending, ""
	case temporalclient.HumanInputTimedOut:
		return HumanInputTimedOut, ""
	case temporalclient.HumanInputRunning:
		if st.ResumeCount > 0 {
			return HumanInputResolved, ""
		}
		return HumanInputNotPending, "the workflow is not waiting on this request"
	default:
		return HumanInputUnknown, "unrecognised workflow state " + st.State
	}
}

func humanInputViewOf(u *auth.User, s sealedHumanInput) humanInputView {
	req := s.req
	v := humanInputView{
		RequestID:      req.RequestID,
		RequestHash:    req.RequestHash,
		RequestVersion: *req.RequestVersion,
		Round:          *req.Round,
		WorkItemID:     req.WorkItemID,
		Service:        s.file.Service,
		Proposal:       s.file.Proposal,
		WorkflowID:     req.Execution.TemporalWorkflowID,
		Agent:          req.Execution.Agent,
		Question:       req.Question,
		Reason:         req.Reason,
		ResponseType:   req.Response.Type,
		Options:        req.Response.Options,
		ContextRefs:    req.ContextRefs,
		Audience:       req.RequestedFrom.Audience,
		CanRespond:     callerCanRespond(u, req),
		CreatedAt:      req.CreatedAt,
		ExpiresAt:      req.ExpiresAt,
	}
	if u.IsAdmin() || u.IsService() {
		v.EligibleActors = req.RequestedFrom.ActorRefs
	}
	return v
}

func (h *Handlers) requireHumanInputReader(w http.ResponseWriter, r *http.Request) (*auth.User, bool) {
	if h.opts.GitReader == nil {
		writeError(w, http.StatusServiceUnavailable, "gitops reader not configured")
		return nil, false
	}
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return nil, false
	}
	return user, true
}

// ListHumanInputs handles GET /api/v1/human-input.
//
// Query: state=pending (default) | all; work_item_id=<id> (optional).
// Only requests the caller may see are listed. state=pending answers 503,
// never a short or empty list that reads as "nothing is waiting", when the
// Temporal client is missing or any candidate's state could not be
// determined.
func (h *Handlers) ListHumanInputs(w http.ResponseWriter, r *http.Request) {
	user, ok := h.requireHumanInputReader(w, r)
	if !ok {
		return
	}
	filter := r.URL.Query().Get("state")
	if filter == "" {
		filter = HumanInputPending
	}
	if filter != HumanInputPending && filter != "all" {
		writeError(w, http.StatusBadRequest, `state must be "pending" or "all"`)
		return
	}
	if filter == HumanInputPending && h.opts.TemporalClient == nil {
		writeError(w, http.StatusServiceUnavailable, "dev-loop Temporal client not configured: pending state cannot be determined")
		return
	}
	workItem := r.URL.Query().Get("work_item_id")

	all, err := h.loadHumanInputRequests()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read human-input requests")
		slog.Error("human_input.list failed", "error", err)
		return
	}
	now := humanInputNow().UTC()
	ctx, cancel := context.WithTimeout(r.Context(), humanInputListBudget)
	defer cancel()
	states := h.newHumanInputStates()
	items := make([]humanInputView, 0)
	undetermined := 0
	for _, s := range all {
		if !canSeeHumanInput(user, s.req) {
			continue
		}
		if workItem != "" && s.req.WorkItemID != workItem {
			continue
		}
		v := humanInputViewOf(user, s)
		v.State, v.StateDetail = states.resolve(ctx, s.req, now, filter != HumanInputPending)
		if filter == HumanInputPending {
			if v.State == HumanInputUnknown {
				undetermined++
			}
			if v.State != HumanInputPending {
				continue
			}
		}
		items = append(items, v)
	}
	if undetermined > 0 {
		slog.Warn("human_input.list_undetermined", "user", user.ID, "undetermined", undetermined)
		writeError(w, http.StatusServiceUnavailable, fmt.Sprintf("pending state could not be determined for %d request(s); retry later or use state=all", undetermined))
		return
	}
	slog.Info("human_input.read", "user", user.ID, "list", true, "state_filter", filter, "count", len(items))
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "count": len(items)})
}

// GetHumanInput handles GET /api/v1/human-input/{request_id}. A request the
// caller may not see is reported as not found, not forbidden.
func (h *Handlers) GetHumanInput(w http.ResponseWriter, r *http.Request) {
	user, ok := h.requireHumanInputReader(w, r)
	if !ok {
		return
	}
	id := chi.URLParam(r, "request_id")
	if !humanInputIDPattern.MatchString(id) {
		writeError(w, http.StatusBadRequest, "request_id must look like hir-<16 hex>")
		return
	}
	s, err := h.findHumanInput(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read human-input requests")
		slog.Error("human_input.get failed", "error", err)
		return
	}
	if s == nil || !canSeeHumanInput(user, s.req) {
		writeError(w, http.StatusNotFound, "human-input request not found: "+id)
		return
	}
	v := humanInputViewOf(user, *s)
	v.State, v.StateDetail = h.newHumanInputStates().resolve(r.Context(), s.req, humanInputNow().UTC(), true)
	slog.Info("human_input.read", "user", user.ID, "request_id", id, "state", v.State)
	writeJSON(w, http.StatusOK, v)
}

// findHumanInput returns the verified request with this id, or nil.
func (h *Handlers) findHumanInput(id string) (*sealedHumanInput, error) {
	all, err := h.loadHumanInputRequests()
	if err != nil {
		return nil, err
	}
	for i := range all {
		if all[i].req.RequestID == id {
			return &all[i], nil
		}
	}
	return nil, nil
}
