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
	"fmt"
	"net/url"
	"strconv"
	"strings"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// Five tools over the human-operator lifecycle recovery surface
// (internal/api/handlers_lifecycle_recovery.go and
// handlers_lifecycle_conflict.go): one evidence read plus four named
// transitions (fence a dead claim, request a handoff off a stuck owner,
// retry a stalled handoff, request reconciliation). None of the four
// mutating tools takes an "operation" or "mode" argument that could pick a
// different transition -- each is its own tool, so the transition performed
// is always the tool NAME, never a runtime value.
//
// None of the five grants GitHub merge or approval authority: they change who
// the lifecycle store says is responsible for an entity phase, never what
// that actor may do with a repository.

// lifecycleRecoveryBody builds the JSON body every mutating recovery route
// shares, converting expected_epoch to a real JSON number (mctl-api rejects
// a string there) and always sending expected_version -- including an empty
// one, which means "match an unset version" rather than "no opinion".
func lifecycleRecoveryBody(req mcplib.CallToolRequest) (map[string]any, *mcplib.CallToolResult) {
	epoch, err := strconv.Atoi(strings.TrimSpace(stringArg(req, "expected_epoch")))
	if err != nil {
		return nil, mcplib.NewToolResultError(fmt.Sprintf("expected_epoch must be an integer: %v", err))
	}
	body := map[string]any{
		"kind":                stringArg(req, "kind"),
		"id":                  stringArg(req, "id"),
		"phase":               stringArg(req, "phase"),
		"expected_owner_type": stringArg(req, "expected_owner_type"),
		"expected_owner_id":   stringArg(req, "expected_owner_id"),
		"expected_epoch":      epoch,
		"expected_version":    stringArg(req, "expected_version"),
		"reason":              stringArg(req, "reason"),
	}
	if v := strings.TrimSpace(stringArg(req, "expected_last_seen_at")); v != "" {
		body["expected_last_seen_at"] = v
	}
	return body, nil
}

func (s *Server) toolInspectLifecycleConflict() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_inspect_lifecycle_conflict",
		mcplib.WithTitleAnnotation("Inspect lifecycle recovery conflict"),
		mcplib.WithReadOnlyHintAnnotation(true),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithDescription(`Read-only evidence for a lifecycle ownership recovery decision: the stored row, the derived view (status, held, dead/stuck/handoff-stalled with the liveness/progress bounds the status was measured against), the legacy DevLoopWorkflow answer, the divergence class between the two, recent transitions, and the EXACT precondition values (expected_owner_type/id, expected_epoch, expected_version, expected_last_seen_at) a follow-up recovery call must send verbatim.

This is the evidence step before mctl_fence_lifecycle_claim, mctl_request_lifecycle_handoff or mctl_retry_lifecycle_handoff. It changes nothing and confers no authority.

If the legacy answer is unobtainable it reports "unavailable" with a reason -- never "no DevLoop": an absent answer and a negative one mean different things to a caller deciding whether a takeover is safe.

Admin-only.`),
		mcplib.WithString("kind",
			mcplib.Required(),
			mcplib.Description(`Entity kind, e.g. "pull-request" or "devloop-proposal".`),
		),
		mcplib.WithString("id",
			mcplib.Required(),
			mcplib.Description(`Entity id, e.g. "mctlhq/mctl-web#42".`),
		),
		mcplib.WithString("phase",
			mcplib.Required(),
			mcplib.Description(`Lifecycle phase, e.g. "review-remediation".`),
		),
	)

	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		q := url.Values{}
		q.Set("kind", stringArg(req, "kind"))
		q.Set("id", stringArg(req, "id"))
		q.Set("phase", stringArg(req, "phase"))
		body, err := s.apiGet(ctx, "/api/v1/lifecycle/ownership/conflict?"+q.Encode())
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to inspect lifecycle conflict: %v", err)), nil
		}
		return mcplib.NewToolResultText(string(body)), nil
	}
	return tool, handler
}

func (s *Server) toolRequestLifecycleReconcile() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_request_lifecycle_reconcile",
		mcplib.WithTitleAnnotation("Request lifecycle reconciliation"),
		mcplib.WithReadOnlyHintAnnotation(false),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithIdempotentHintAnnotation(true),
		mcplib.WithDescription(`Mutates the lifecycle ownership store. Performs exactly one transition: appends a reconcile-requested event for one entity phase. It changes NO ownership column -- owner, epoch and state are untouched -- so it never takes a claim from anybody and confers no GitHub merge or approval authority.

No licensing condition is required: unlike fence or handoff, this is a request for attention, not a claim on the row. But every precondition still fails closed -- expected_owner_type/id, expected_epoch and expected_version must match what the store currently holds, or the call is refused with a 412 naming what moved, and NO event is appended. Read mctl_inspect_lifecycle_conflict first for the exact values to send.

Idempotent: repeating the same call while the preconditions still match appends another identical event and is safe to retry.

Admin-only.`),
		mcplib.WithString("kind",
			mcplib.Required(),
			mcplib.Description(`Entity kind, e.g. "pull-request" or "devloop-proposal".`),
		),
		mcplib.WithString("id",
			mcplib.Required(),
			mcplib.Description(`Entity id, e.g. "mctlhq/mctl-web#42".`),
		),
		mcplib.WithString("phase",
			mcplib.Required(),
			mcplib.Description(`Lifecycle phase, e.g. "review-remediation".`),
		),
		mcplib.WithString("expected_owner_type",
			mcplib.Required(),
			mcplib.Description("Current owner type, read from mctl_inspect_lifecycle_conflict."),
		),
		mcplib.WithString("expected_owner_id",
			mcplib.Required(),
			mcplib.Description("Current owner id, read from mctl_inspect_lifecycle_conflict."),
		),
		mcplib.WithString("expected_epoch",
			mcplib.Required(),
			mcplib.Description("Current fencing epoch, read from mctl_inspect_lifecycle_conflict."),
		),
		mcplib.WithString("expected_version",
			mcplib.Required(),
			mcplib.Description(`Current entity version, read from mctl_inspect_lifecycle_conflict. Send "" to match an unset version.`),
		),
		mcplib.WithString("expected_last_seen_at",
			mcplib.Description("Optional extra pin on the owner's last_seen_at (RFC3339), read from mctl_inspect_lifecycle_conflict."),
		),
		mcplib.WithString("reason",
			mcplib.Required(),
			mcplib.Description("Why reconciliation is being requested. Recorded on the audit entry and the lifecycle event."),
		),
	)

	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		body, errResult := lifecycleRecoveryBody(req)
		if errResult != nil {
			return errResult, nil
		}
		respBody, err := s.apiPostJSON(ctx, "/api/v1/lifecycle/ownership/recovery/reconcile", body)
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to request lifecycle reconcile: %v", err)), nil
		}
		return mcplib.NewToolResultText(string(respBody)), nil
	}
	return tool, handler
}

func (s *Server) toolFenceLifecycleClaim() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_fence_lifecycle_claim",
		mcplib.WithTitleAnnotation("Fence a dead lifecycle claim"),
		mcplib.WithReadOnlyHintAnnotation(false),
		mcplib.WithDestructiveHintAnnotation(true),
		mcplib.WithIdempotentHintAnnotation(false),
		mcplib.WithDescription(`DESTRUCTIVE: mutates the lifecycle ownership store. Performs exactly one transition: releases (fences) a claim whose owner the server re-derives as DEAD -- re-checked server-side under the store's own advisory lock, so a caller may not assert death, only ask for the question to be re-asked; refused with a 409 if the owner is still alive. Installs NO successor: the row moves to "released" with its fencing epoch incremented by the database (never by a caller-supplied value), and the fenced owner stays named on the row for forensics.

Every precondition fails closed: expected_owner_type/id, expected_epoch and expected_version must match what the store currently holds, or the call is refused with a 412 (something moved) and nothing changes. Read mctl_inspect_lifecycle_conflict first for the exact values to send and to confirm the owner is actually dead, not merely stuck.

This confers NO GitHub merge or approval authority and cannot install an arbitrary owner -- it only vacates a dead claim so an ordinary Acquire can take it.

Requires confirm="yes".`),
		mcplib.WithString("kind",
			mcplib.Required(),
			mcplib.Description(`Entity kind, e.g. "pull-request" or "devloop-proposal".`),
		),
		mcplib.WithString("id",
			mcplib.Required(),
			mcplib.Description(`Entity id, e.g. "mctlhq/mctl-web#42".`),
		),
		mcplib.WithString("phase",
			mcplib.Required(),
			mcplib.Description(`Lifecycle phase, e.g. "review-remediation".`),
		),
		mcplib.WithString("expected_owner_type",
			mcplib.Required(),
			mcplib.Description("Current owner type, read from mctl_inspect_lifecycle_conflict."),
		),
		mcplib.WithString("expected_owner_id",
			mcplib.Required(),
			mcplib.Description("Current owner id, read from mctl_inspect_lifecycle_conflict."),
		),
		mcplib.WithString("expected_epoch",
			mcplib.Required(),
			mcplib.Description("Current fencing epoch, read from mctl_inspect_lifecycle_conflict."),
		),
		mcplib.WithString("expected_version",
			mcplib.Required(),
			mcplib.Description(`Current entity version, read from mctl_inspect_lifecycle_conflict. Send "" to match an unset version.`),
		),
		mcplib.WithString("expected_last_seen_at",
			mcplib.Description("Optional extra pin on the owner's last_seen_at (RFC3339), read from mctl_inspect_lifecycle_conflict."),
		),
		mcplib.WithString("reason",
			mcplib.Required(),
			mcplib.Description("Why this claim is being fenced. Recorded on the audit entry and the lifecycle event."),
		),
		mcplib.WithString("confirm",
			mcplib.Description(`Type "yes" to confirm -- only after showing the user what will happen and receiving explicit agreement.`),
		),
	)

	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		args := req.GetArguments()
		subject := fmt.Sprintf("fence the claim on %s/%s phase %s, releasing it with no successor",
			stringArg(req, "kind"), stringArg(req, "id"), stringArg(req, "phase"))
		if r := requireConfirm(args, subject); r != nil {
			return r, nil
		}
		body, errResult := lifecycleRecoveryBody(req)
		if errResult != nil {
			return errResult, nil
		}
		respBody, err := s.apiPostJSON(ctx, "/api/v1/lifecycle/ownership/recovery/fence", body)
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to fence lifecycle claim: %v", err)), nil
		}
		return mcplib.NewToolResultText(string(respBody)), nil
	}
	return tool, handler
}

func (s *Server) toolRequestLifecycleHandoff() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_request_lifecycle_handoff",
		mcplib.WithTitleAnnotation("Request a lifecycle handoff off a stuck owner"),
		mcplib.WithReadOnlyHintAnnotation(false),
		mcplib.WithDestructiveHintAnnotation(true),
		mcplib.WithIdempotentHintAnnotation(false),
		mcplib.WithDescription(`DESTRUCTIVE: mutates the lifecycle ownership store. Performs exactly one transition: starts a handoff off an owner the server re-derives as STUCK -- alive, but has effected no progress within its phase's bound -- toward the named to_owner. Refused with a 409 on a healthy owner (not licensed), a dead one (use mctl_fence_lifecycle_claim instead -- handing off a dead claim just produces a second stuck machine), or one already handing off (use mctl_retry_lifecycle_handoff instead of layering a second handoff on top).

The outgoing owner is NOT removed: like an ordinary handoff, the row stays owned until to_owner completes it through its own normal path, so an incomplete handoff stays a visible state rather than a zero-owner gap. The fencing epoch is UNCHANGED.

Every precondition fails closed: expected_owner_type/id, expected_epoch and expected_version must match what the store currently holds, or the call is refused with a 412 and nothing changes. Read mctl_inspect_lifecycle_conflict first for the exact values to send and to confirm the owner is actually stuck.

This confers NO GitHub merge or approval authority and does not itself install to_owner as the acting owner -- that still requires to_owner's own completion of the handoff.

Requires confirm="yes".`),
		mcplib.WithString("kind",
			mcplib.Required(),
			mcplib.Description(`Entity kind, e.g. "pull-request" or "devloop-proposal".`),
		),
		mcplib.WithString("id",
			mcplib.Required(),
			mcplib.Description(`Entity id, e.g. "mctlhq/mctl-web#42".`),
		),
		mcplib.WithString("phase",
			mcplib.Required(),
			mcplib.Description(`Lifecycle phase, e.g. "review-remediation".`),
		),
		mcplib.WithString("expected_owner_type",
			mcplib.Required(),
			mcplib.Description("Current owner type, read from mctl_inspect_lifecycle_conflict."),
		),
		mcplib.WithString("expected_owner_id",
			mcplib.Required(),
			mcplib.Description("Current owner id, read from mctl_inspect_lifecycle_conflict."),
		),
		mcplib.WithString("expected_epoch",
			mcplib.Required(),
			mcplib.Description("Current fencing epoch, read from mctl_inspect_lifecycle_conflict."),
		),
		mcplib.WithString("expected_version",
			mcplib.Required(),
			mcplib.Description(`Current entity version, read from mctl_inspect_lifecycle_conflict. Send "" to match an unset version.`),
		),
		mcplib.WithString("expected_last_seen_at",
			mcplib.Description("Optional extra pin on the owner's last_seen_at (RFC3339), read from mctl_inspect_lifecycle_conflict."),
		),
		mcplib.WithString("to_owner_type",
			mcplib.Required(),
			mcplib.Description(`Owner type the handoff targets, e.g. "pr-steward".`),
		),
		mcplib.WithString("to_owner_id",
			mcplib.Required(),
			mcplib.Description("Owner id the handoff targets."),
		),
		mcplib.WithString("reason",
			mcplib.Required(),
			mcplib.Description("Why this handoff is being requested. Recorded on the audit entry and the lifecycle event."),
		),
		mcplib.WithString("confirm",
			mcplib.Description(`Type "yes" to confirm -- only after showing the user what will happen and receiving explicit agreement.`),
		),
	)

	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		args := req.GetArguments()
		subject := fmt.Sprintf("start a handoff of %s/%s phase %s to %s/%s",
			stringArg(req, "kind"), stringArg(req, "id"), stringArg(req, "phase"),
			stringArg(req, "to_owner_type"), stringArg(req, "to_owner_id"))
		if r := requireConfirm(args, subject); r != nil {
			return r, nil
		}
		body, errResult := lifecycleRecoveryBody(req)
		if errResult != nil {
			return errResult, nil
		}
		body["to_owner_type"] = stringArg(req, "to_owner_type")
		body["to_owner_id"] = stringArg(req, "to_owner_id")
		respBody, err := s.apiPostJSON(ctx, "/api/v1/lifecycle/ownership/recovery/handoff/request", body)
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to request lifecycle handoff: %v", err)), nil
		}
		return mcplib.NewToolResultText(string(respBody)), nil
	}
	return tool, handler
}

func (s *Server) toolRetryLifecycleHandoff() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_retry_lifecycle_handoff",
		mcplib.WithTitleAnnotation("Retry a stalled lifecycle handoff"),
		mcplib.WithReadOnlyHintAnnotation(false),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithIdempotentHintAnnotation(true),
		mcplib.WithDescription(`Mutates the lifecycle ownership store. Performs exactly one transition: re-arms the clocks (handoff_started_at AND last_seen_at) of a handoff the server re-derives as STALLED -- started, and never completed within the phase's liveness bound -- for the SAME target. Refused if the row is not handing off at all, or if the handoff is still within its bound (not yet stalled).

Owner, target, state and fencing epoch are all UNCHANGED -- this does not retarget the handoff or take it from anybody, only extends how long the named target has left to complete it.

Every precondition fails closed: expected_owner_type/id, expected_epoch and expected_version must match what the store currently holds, or the call is refused with a 412 and nothing changes. Read mctl_inspect_lifecycle_conflict first for the exact values to send and to confirm the handoff has actually stalled.

This confers NO GitHub merge or approval authority.

The row comes back ALIVE for one liveness bound: that is the extension, and it also means mctl_fence_lifecycle_claim and recovery stop applying to this row until the bound passes, and a second retry is refused as not-yet-stalled until then. Repeating the call while the handoff is still stalled re-arms the same clocks again and is safe to retry.

Admin-only.`),
		mcplib.WithString("kind",
			mcplib.Required(),
			mcplib.Description(`Entity kind, e.g. "pull-request" or "devloop-proposal".`),
		),
		mcplib.WithString("id",
			mcplib.Required(),
			mcplib.Description(`Entity id, e.g. "mctlhq/mctl-web#42".`),
		),
		mcplib.WithString("phase",
			mcplib.Required(),
			mcplib.Description(`Lifecycle phase, e.g. "review-remediation".`),
		),
		mcplib.WithString("expected_owner_type",
			mcplib.Required(),
			mcplib.Description("Current owner type (the OUTGOING owner), read from mctl_inspect_lifecycle_conflict."),
		),
		mcplib.WithString("expected_owner_id",
			mcplib.Required(),
			mcplib.Description("Current owner id (the OUTGOING owner), read from mctl_inspect_lifecycle_conflict."),
		),
		mcplib.WithString("expected_epoch",
			mcplib.Required(),
			mcplib.Description("Current fencing epoch, read from mctl_inspect_lifecycle_conflict."),
		),
		mcplib.WithString("expected_version",
			mcplib.Required(),
			mcplib.Description(`Current entity version, read from mctl_inspect_lifecycle_conflict. Send "" to match an unset version.`),
		),
		mcplib.WithString("expected_last_seen_at",
			mcplib.Description("Optional extra pin on the owner's last_seen_at (RFC3339), read from mctl_inspect_lifecycle_conflict."),
		),
		mcplib.WithString("reason",
			mcplib.Required(),
			mcplib.Description("Why this handoff retry is being requested. Recorded on the audit entry and the lifecycle event."),
		),
	)

	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		body, errResult := lifecycleRecoveryBody(req)
		if errResult != nil {
			return errResult, nil
		}
		respBody, err := s.apiPostJSON(ctx, "/api/v1/lifecycle/ownership/recovery/handoff/retry", body)
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("Failed to retry lifecycle handoff: %v", err)), nil
		}
		return mcplib.NewToolResultText(string(respBody)), nil
	}
	return tool, handler
}
