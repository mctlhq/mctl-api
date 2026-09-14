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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/mctlhq/mctl-api/internal/lifecycle"
	"github.com/mctlhq/mctl-api/internal/temporalclient"
)

// lifecycleLegacyFanoutCap bounds the legacy probe in list mode.
//
// The probe is one HTTP call per record against the dev-loop describe route,
// issued serially, and an operator listing the store is not asking to wait
// through fifty of them. Beyond the cap the records are still returned, with
// their legacy block unavailable and `truncated` set — a partial answer that
// says it is partial, rather than a complete one that took a minute.
const lifecycleLegacyFanoutCap = 10

// lifecycleEventsDefaultLimit bounds an `include_events` read per record.
const lifecycleEventsDefaultLimit = 20

// The three legacy answers, mirroring lifecycle.LegacyAnswer for the wire.
// Three-valued on purpose: the shepherd's own probe returns a bool and folds
// "could not tell" into "not owned", which is the collapse ADR-010 exists to
// undo. Reporting it here as a bool would reintroduce it in the one surface an
// operator uses to check the contract.
const (
	legacyAnswerOwned   = "owned"
	legacyAnswerFree    = "free"
	legacyAnswerUnknown = "unknown"
)

// lifecycleLegacy is the old mechanism's view of one entity: is a live
// DevLoopWorkflow driving it?
//
// Available is false whenever the question could not be put — no proposal_ref
// on the record, the describe route unreachable. It is never omitted and never
// null: an absent legacy block would read as "no DevLoop", which is an answer
// this tool did not obtain.
type lifecycleLegacy struct {
	Available bool   `json:"available"`
	Answer    string `json:"answer"`
	Reason    string `json:"reason,omitempty"`

	WorkflowID     string `json:"workflow_id,omitempty"`
	Status         string `json:"status,omitempty"`
	ShepherdInLoop *bool  `json:"shepherd_in_loop,omitempty"`
}

// apiOwnershipRecord mirrors the API's ownershipResponse: the record's own
// fields at the top level, plus the derived view under `derived`.
type apiOwnershipRecord struct {
	lifecycle.Ownership
	Derived lifecycle.Derived `json:"derived"`
}

// lifecycleRecord is one entry of the envelope. Every sub-object is always
// present, because in this vocabulary an absent answer and a negative answer
// are different things and a consumer that has to tell them apart from the
// presence of a JSON key will eventually get it wrong.
type lifecycleRecord struct {
	Ownership  *lifecycle.Ownership `json:"ownership"`
	Derived    lifecycle.Derived    `json:"derived"`
	Legacy     lifecycleLegacy      `json:"legacy"`
	Divergence lifecycle.Divergence `json:"divergence"`
	Events     lifecycleEvents      `json:"events"`
}

// lifecycleEvents is the transition history, and whether it was obtained.
//
// An empty list from a record with no transitions and an empty list from a
// failed read are the same JSON, and they mean opposite things to the one
// reader who asks for events at all: somebody reconstructing a lost acquire
// after the fact. So the list carries its own availability, the same way
// `legacy` does -- reading events must not fail the ownership read, which is
// not in tension with saying it did not happen.
type lifecycleEvents struct {
	Available bool              `json:"available"`
	Reason    string            `json:"reason,omitempty"`
	Items     []json.RawMessage `json:"items"`
}

func (s *Server) toolGetLifecycleOwnership() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_get_lifecycle_ownership",
		mcplib.WithTitleAnnotation("Read lifecycle ownership"),
		mcplib.WithReadOnlyHintAnnotation(true),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithDescription(`Read the lifecycle ownership store (ADR-010): who is responsible for an entity phase, whether that owner is still alive, and whether the store agrees with the old DevLoopWorkflow liveness check.

Two modes, one response shape. Give `+"`id`"+` (or `+"`pr_url`"+`) with `+"`kind`"+` and `+"`phase`"+` to read ONE entity; give none of them to list what the store holds, optionally filtered by `+"`state`"+` and `+"`owner_type`"+`. `+"`records`"+` is always an array — length 0 or 1 in record mode — so a caller never has to decide which of two types it is parsing before it can read the answer.

Each record carries: ownership (the stored row), derived (status, held, dead, and the liveness/progress bounds the status was measured against), legacy (whether a live DevLoopWorkflow is driving the same entity), divergence (how the two compare), and events when include_events=true.

The legacy and events blocks each carry their own "available" flag plus a "reason". An empty history, or a legacy answer with available=false, is something this tool could not obtain — never something it measured. That distinction matters most to the caller reconstructing what happened after the fact, which is the only caller who asks for events at all.

READ THE STATUS VOCABULARY BEFORE ACTING ON IT. It is closed: healthy, stuck, dead, handing-off, handoff-stalled, released, terminal, unknown. Only "dead" licenses another actor to TAKE the entity (ADR-010 §4). "stuck" means alive but achieving nothing — that calls for a human, not for a second machine that will be equally stuck. "held" is the takeover predicate and is carried separately from status on purpose: a handing-off row past its liveness bound reports the more specific status handoff-stalled while being dead and recoverable, so reading takeover off the status string gets it backwards.

A 503 means the store did not answer. It means UNKNOWN, never UNOWNED. An unreachable store must not be read as permission to act.

The divergence class store-permits-old-forbids is the only dangerous one: the store would license an action the old mechanism forbids, i.e. taking a pull request another machine is actively pushing to. One of those is a stop-the-rollout event, not a metric to watch trend downward.

This tool grants no authority. Ownership says who is responsible; it never says what they are permitted to do, and it confers no GitHub merge or approval rights.

Admin-only. include_legacy defaults to true and costs one dev-loop describe call per record, capped at `+strconv.Itoa(lifecycleLegacyFanoutCap)+` records in list mode (beyond that the remaining records come back with legacy unavailable and truncated=true).`),
		mcplib.WithString("kind",
			mcplib.Description(`Entity kind, e.g. "pull-request" or "proposal". Required with id or pr_url.`),
		),
		mcplib.WithString("phase",
			mcplib.Description(`Lifecycle phase, e.g. "review-remediation". Required with id or pr_url.`),
		),
		mcplib.WithString("id",
			mcplib.Description(`Entity id, e.g. "mctlhq/mctl-web#42". Provide this or pr_url, not both. Omit both to list.`),
		),
		mcplib.WithString("pr_url",
			mcplib.Description(`Full pull request URL, e.g. https://github.com/mctlhq/mctl-web/pull/42 — the entity id is derived from it. Provide this or id, not both.`),
		),
		mcplib.WithString("state",
			mcplib.Description(`List filter: stored state ("active", "handing-off", "released", "terminal"). Ignored in record mode.`),
		),
		mcplib.WithString("owner_type",
			mcplib.Description(`List filter: owner TYPE ("shepherd", "pr-steward", "devloop-workflow"), never a specific owner id. Ignored in record mode.`),
		),
		mcplib.WithString("limit",
			mcplib.Description("List mode: maximum records to return. Ignored in record mode."),
		),
		mcplib.WithString("include_events",
			mcplib.Description(`"true" to attach the transition history to each record. Off by default — it is a second read per record.`),
		),
		mcplib.WithString("include_legacy",
			mcplib.Description(`"false" to skip the DevLoopWorkflow liveness probe. Defaults to true; without it the divergence class is always legacy-unknown.`),
		),
	)

	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		kind := strings.TrimSpace(stringArg(req, "kind"))
		phase := strings.TrimSpace(stringArg(req, "phase"))
		id := strings.TrimSpace(stringArg(req, "id"))
		prURL := strings.TrimSpace(stringArg(req, "pr_url"))
		includeEvents := parseBoolArg(stringArg(req, "include_events"), false)
		includeLegacy := parseBoolArg(stringArg(req, "include_legacy"), true)

		if id != "" && prURL != "" {
			return mcplib.NewToolResultError("provide id or pr_url, not both"), nil
		}
		if prURL != "" {
			derivedID, err := entityIDForPullRequestURL(prURL)
			if err != nil {
				return mcplib.NewToolResultError(fmt.Sprintf("invalid pr_url: %v", err)), nil
			}
			id = derivedID
			// A pull request URL determines the kind. Silently querying a
			// contradictory one would answer "no record" for a lookup that was
			// never going to match -- an empty result reported as a fact.
			if kind != "" && kind != lifecycle.KindPullRequest {
				return mcplib.NewToolResultError(fmt.Sprintf(
					"pr_url implies kind %q, but kind=%q was given; drop one",
					lifecycle.KindPullRequest, kind)), nil
			}
			kind = lifecycle.KindPullRequest
		}

		mode := "list"
		if id != "" {
			mode = "record"
			if kind == "" || phase == "" {
				return mcplib.NewToolResultError("kind and phase are required when id or pr_url is given"), nil
			}
		}

		records, truncated, errResult := s.lifecycleFetch(ctx, mode, kind, phase, id, req)
		if errResult != nil {
			return errResult, nil
		}

		out := make([]lifecycleRecord, 0, len(records))
		for i := range records {
			// The cap applies to the PROBE, not to the records: a record past
			// it is still returned, with its legacy block saying why it is
			// empty. Dropping records instead would make a list read's length
			// depend on an option that is supposed to add detail to it.
			probe := includeLegacy && i < lifecycleLegacyFanoutCap
			if includeLegacy && i >= lifecycleLegacyFanoutCap {
				truncated = true
			}
			out = append(out, s.lifecycleRecordFor(ctx, &records[i], probe, includeLegacy, includeEvents))
		}

		envelope := map[string]any{
			"mode": mode,
			"query": map[string]any{
				"kind": kind, "phase": phase, "id": id,
				"state":      strings.TrimSpace(stringArg(req, "state")),
				"owner_type": strings.TrimSpace(stringArg(req, "owner_type")),
				"limit":      strings.TrimSpace(stringArg(req, "limit")),
			},
			"count":     len(out),
			"records":   out,
			"truncated": truncated,
			"as_of":     time.Now().UTC().Format(time.RFC3339),
		}
		body, err := json.Marshal(envelope)
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to encode lifecycle ownership: %v", err)), nil
		}
		return mcplib.NewToolResultText(string(body)), nil
	}

	return tool, handler
}

// lifecycleFetch reads the store and returns the raw records.
//
// The 503 is passed through VERBATIM rather than translated, because every
// paraphrase of it so far has drifted toward "nothing owns this". The error
// result carries the API's own sentence, which says the store is not
// configured, not that the entity is free.
func (s *Server) lifecycleFetch(
	ctx context.Context, mode, kind, phase, id string, req mcplib.CallToolRequest,
) ([]apiOwnershipRecord, bool, *mcplib.CallToolResult) {
	q := url.Values{}
	path := "/api/v1/lifecycle/ownership"
	if mode == "record" {
		path += "/record"
		q.Set("kind", kind)
		q.Set("phase", phase)
		q.Set("id", id)
	} else {
		for _, name := range []string{"kind", "phase", "state", "owner_type", "limit"} {
			if v := strings.TrimSpace(stringArg(req, name)); v != "" {
				q.Set(name, v)
			}
		}
	}
	body, status, err := s.apiGetStatus(ctx, path+"?"+q.Encode())
	if err != nil {
		return nil, false, mcplib.NewToolResultError(fmt.Sprintf("Failed to read lifecycle ownership: %v", err))
	}

	switch {
	case status == http.StatusNotFound && mode == "record" && isAPIErrorBody(body):
		// Gated on the body being the API's own {"error": ...} envelope: chi
		// answers a MISSING ROUTE with the same 404 and the plain text "404
		// page not found". This package can be pointed at any apiURL, so
		// against an mctl-api predating /lifecycle/ownership/record an
		// unguarded arm would report count: 0 — indistinguishable from "the
		// store holds nothing", which is the post-deploy check itself.
		// A real answer: the store holds nothing for this entity phase. Empty
		// array, not an error — and emphatically not the same as the 503 below.
		return nil, false, nil
	case status >= 400:
		return nil, false, mcplib.NewToolResultError(fmt.Sprintf(
			"lifecycle ownership read returned %d: %s", status, strings.TrimSpace(string(body))))
	}

	if mode == "record" {
		var one apiOwnershipRecord
		if err := json.Unmarshal(body, &one); err != nil {
			return nil, false, mcplib.NewToolResultError(fmt.Sprintf("Failed to parse lifecycle record: %v", err))
		}
		return []apiOwnershipRecord{one}, false, nil
	}

	var listed struct {
		Ownership []apiOwnershipRecord `json:"ownership"`
	}
	if err := json.Unmarshal(body, &listed); err != nil {
		return nil, false, mcplib.NewToolResultError(fmt.Sprintf("Failed to parse lifecycle ownership list: %v", err))
	}
	// The STORE truncates too, and used to do it invisibly here: Store.List
	// applies a default limit of 100 when the caller sends none and clamps
	// anything above 500. Reporting `truncated: false` while returning 100 of
	// 250 rows tells the operator this is everything the store holds -- and
	// `count` cannot stand in for it, since 100-of-100 and 100-of-400 produce
	// an identical envelope.
	//
	// A full page is REPORTED as truncated even when it happens to be the last
	// one. That over-reports exactly one case, the page boundary, and never
	// under-reports -- the safe direction for a field whose whole job is to
	// say "there may be more".
	return listed.Ownership, len(listed.Ownership) >= effectiveListLimit(req), nil
}

// effectiveListLimit mirrors lifecycle.Store.List's own bounds
// (internal/lifecycle/store.go): absent or unparseable means 100, and anything
// above 500 is clamped there.
func effectiveListLimit(req mcplib.CallToolRequest) int {
	const (
		defaultLimit = 100
		maxLimit     = 500
	)
	n, err := strconv.Atoi(strings.TrimSpace(stringArg(req, "limit")))
	if err != nil || n <= 0 {
		return defaultLimit
	}
	if n > maxLimit {
		return maxLimit
	}
	return n
}

// lifecycleRecordFor assembles one envelope entry.
func (s *Server) lifecycleRecordFor(
	ctx context.Context, rec *apiOwnershipRecord, probe, includeLegacy, includeEvents bool,
) lifecycleRecord {
	owned := rec.Ownership
	// The derived view comes from the server so there is ONE derivation, but
	// an empty Status means the response carried no `derived` block at all --
	// an mctl-api older than the one that added it, which this package can be
	// pointed at (cmd/mcp/main.go takes an arbitrary apiURL). The zero value
	// is not a neutral default here: held=false plus a legacy answer of
	// `owned` classifies as the dangerous store-permits-old-forbids, so
	// trusting it would FABRICATE the stop-the-rollout class for every held
	// record. Status is the sentinel because Derive never returns it empty.
	//
	// Deriving locally is exact rather than a guess: this binary carries the
	// same Derive and the same bounds table the server uses, and the record
	// carries every input it needs.
	derived := rec.Derived
	if derived.Status == "" {
		derived = lifecycle.Derive(&owned, time.Now().UTC())
	}
	out := lifecycleRecord{
		Ownership: &owned,
		Derived:   derived,
		Events:    lifecycleEvents{Items: []json.RawMessage{}},
	}

	switch {
	case !includeLegacy:
		out.Legacy = lifecycleLegacy{Answer: legacyAnswerUnknown, Reason: "include_legacy=false"}
	case !probe:
		out.Legacy = lifecycleLegacy{
			Answer: legacyAnswerUnknown,
			Reason: fmt.Sprintf("legacy probe capped at %d records per call", lifecycleLegacyFanoutCap),
		}
	default:
		out.Legacy = s.lifecycleLegacyFor(ctx, owned)
	}

	// The store answered — this record is proof of it — so storeReadable is
	// true here by construction. An unreachable store never reaches this
	// function: it fails the fetch above and the tool returns the API's 503.
	out.Divergence = lifecycle.ClassifyDerived(&owned, derived, true, legacyAnswerToEnum(out.Legacy.Answer))

	if includeEvents {
		out.Events = s.lifecycleEventsFor(ctx, owned)
	}
	return out
}

// lifecycleLegacyFor asks the old mechanism about one entity.
//
// The mapping mirrors run_shepherd.py's probe, with one difference that is the
// whole point: every path that means "we could not tell" answers UNKNOWN here,
// where the shepherd's bool answers False and thereby says "nobody owns this".
func (s *Server) lifecycleLegacyFor(ctx context.Context, o lifecycle.Ownership) lifecycleLegacy {
	if strings.TrimSpace(o.ProposalRef) == "" {
		// Not "no DevLoop": no way to ask. A pull request row written by
		// something other than the DevLoop carries no proposal ref, and the
		// workflow id is not reconstructible from anything else on the record.
		return lifecycleLegacy{Answer: legacyAnswerUnknown, Reason: "record carries no proposal_ref"}
	}
	workflowID, err := temporalclient.WorkflowIDForProposalRef(o.ProposalRef)
	switch {
	case errors.Is(err, temporalclient.ErrNoDevLoopForProposalRef):
		// A slug with no issue-<N>- prefix (incident-*, anything pre-Temporal)
		// never had a DevLoopWorkflow. That is an answer, not a failure.
		return lifecycleLegacy{
			Available: true,
			Answer:    legacyAnswerFree,
			Reason:    fmt.Sprintf("proposal_ref %q names no DevLoopWorkflow", o.ProposalRef),
		}
	case err != nil:
		// A ref this code could not read. NOT "no DevLoop": the question was
		// never put, and answering `free` here would classify a genuinely
		// unowned-and-driven entity as agreement.
		return lifecycleLegacy{Answer: legacyAnswerUnknown, Reason: err.Error()}
	}

	body, status, err := s.apiGetStatus(ctx, "/api/v1/agents/dev-loop/"+url.PathEscape(workflowID))
	if err != nil {
		return lifecycleLegacy{
			Answer: legacyAnswerUnknown, WorkflowID: workflowID,
			Reason: fmt.Sprintf("dev-loop describe failed: %v", err),
		}
	}
	if status == http.StatusNotFound {
		return lifecycleLegacy{
			Available: true, Answer: legacyAnswerFree, WorkflowID: workflowID,
			Reason: "no such DevLoopWorkflow (never started, or past retention)",
		}
	}
	if status >= 400 {
		return lifecycleLegacy{
			Answer: legacyAnswerUnknown, WorkflowID: workflowID,
			Reason: fmt.Sprintf("dev-loop describe returned %d", status),
		}
	}

	var described struct {
		Status string `json:"status"`
		// Both fields are pointers so an absent key is distinguishable from
		// false. `shepherd_in_loop` alone cannot answer: mctl-api reports
		// false both for a live execution declining to shepherd and for a
		// query it could not complete, and those mean opposite things here.
		ShepherdInLoop      *bool `json:"shepherd_in_loop"`
		ShepherdInLoopKnown *bool `json:"shepherd_in_loop_known"`
	}
	if err := json.Unmarshal(body, &described); err != nil {
		return lifecycleLegacy{
			Answer: legacyAnswerUnknown, WorkflowID: workflowID,
			Reason: fmt.Sprintf("dev-loop describe unreadable: %v", err),
		}
	}

	out := lifecycleLegacy{
		Available: true, WorkflowID: workflowID,
		Status: described.Status, ShepherdInLoop: described.ShepherdInLoop,
	}
	switch {
	case described.Status != "Running":
		out.Answer = legacyAnswerFree
	case described.ShepherdInLoop == nil:
		// An mctl-api too old to serve the field. Running is not the same as
		// ticking, and we cannot tell which this is.
		out.Available = false
		out.Answer = legacyAnswerUnknown
		out.Reason = "running, but the describe route did not report shepherd_in_loop"
	case described.ShepherdInLoopKnown != nil && !*described.ShepherdInLoopKnown:
		// The route reported false as a FALLBACK: its query to the workflow
		// did not complete (an old worker without the handler, a worker
		// outage, a timeout). The value is false and the answer is unknown.
		out.Available = false
		out.Answer = legacyAnswerUnknown
		out.Reason = "running, but the shepherd_in_loop query did not complete"
	case *described.ShepherdInLoop:
		out.Answer = legacyAnswerOwned
	default:
		// Running and declining to shepherd: a real "does not drive this".
		out.Answer = legacyAnswerFree
	}
	return out
}

func (s *Server) lifecycleEventsFor(ctx context.Context, o lifecycle.Ownership) lifecycleEvents {
	q := url.Values{}
	q.Set("kind", o.Entity.Kind)
	q.Set("id", o.Entity.ID)
	q.Set("phase", o.Phase)
	q.Set("limit", strconv.Itoa(lifecycleEventsDefaultLimit))
	empty := func(reason string) lifecycleEvents {
		// Events are detail, never the answer: a failure to read them must not
		// fail the ownership read the caller actually asked for -- but it must
		// say so, or an empty history and an unread one are the same JSON.
		return lifecycleEvents{Reason: reason, Items: []json.RawMessage{}}
	}
	body, status, err := s.apiGetStatus(ctx, "/api/v1/lifecycle/events?"+q.Encode())
	if err != nil {
		return empty(fmt.Sprintf("events read failed: %v", err))
	}
	if status >= 400 {
		return empty(fmt.Sprintf("events read returned %d", status))
	}
	var listed struct {
		Events []json.RawMessage `json:"events"`
	}
	if err := json.Unmarshal(body, &listed); err != nil {
		return empty(fmt.Sprintf("events response unreadable: %v", err))
	}
	if listed.Events == nil {
		listed.Events = []json.RawMessage{}
	}
	return lifecycleEvents{Available: true, Items: listed.Events}
}

func legacyAnswerToEnum(answer string) lifecycle.LegacyAnswer {
	switch answer {
	case legacyAnswerOwned:
		return lifecycle.LegacyOwned
	case legacyAnswerFree:
		return lifecycle.LegacyFree
	default:
		return lifecycle.LegacyUnknown
	}
}

// parseBoolArg reads an optional boolean argument.
//
// Every tool in this server takes strings, so this is "true"/"false" text. An
// unrecognised value falls back to the DEFAULT rather than to false: a typo in
// include_legacy must not silently turn the divergence column into
// legacy-unknown for every record and look like a real measurement.
func parseBoolArg(raw string, fallback bool) bool {
	v, err := strconv.ParseBool(strings.TrimSpace(raw))
	if err != nil {
		return fallback
	}
	return v
}

// entityIDForPullRequestURL turns a pull request URL into the entity id the
// store keys on — "mctlhq/mctl-web#42", the same string
// EntityRef.for_pull_request builds on the Python side.
func entityIDForPullRequestURL(prURL string) (string, error) {
	m := pullRequestURLPattern.FindStringSubmatch(strings.TrimSpace(prURL))
	if m == nil {
		return "", fmt.Errorf("not a well-formed GitHub pull request URL: %q", prURL)
	}
	return fmt.Sprintf("%s/%s#%s", m[1], m[2], m[3]), nil
}

// pullRequestURLPattern accepts any owner, unlike the issue URL pattern in
// temporalclient: that one derives a workflow id whose owner is pinned to
// mctlhq, while this one only builds a lookup key, and refusing a fork or a
// second org here would refuse a read that the store can perfectly well answer.
var pullRequestURLPattern = regexp.MustCompile(
	`^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/pull/([0-9]+)/?$`)

// isAPIErrorBody reports whether a body is the API's {"error": "..."} envelope.
func isAPIErrorBody(body []byte) bool {
	var envelope struct {
		Error string `json:"error"`
	}
	return json.Unmarshal(body, &envelope) == nil && envelope.Error != ""
}
