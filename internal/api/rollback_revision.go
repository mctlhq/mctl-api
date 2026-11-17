package api

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/deployplan"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// Rollback by revision (mctl-api#1048).
//
// rollback-revision restores a service to the state one of its DeployRecords
// describes. The caller names the deployment; the commit and the digest the
// workflow acts on are read from the record here, never from the request,
// because they decide what gets written to mctl-gitops.

const (
	rollbackRevisionOp = "rollback-revision"

	codeRollbackDeploymentNotFound  = "rollback_deployment_not_found"
	codeRollbackDeploymentNotUsable = "rollback_deployment_not_usable"
	codeRollbackStoreUnavailable    = "rollback_store_unavailable"
	codeRollbackServerSetInBody     = "rollback_target_is_server_set"
	rollbackDeploymentIDParam       = "deployment_id"
	rollbackTargetCommitParam       = "target_commit"
	rollbackExpectedDigestParam     = "expected_digest"
)

// rollbackServerSetParams are inputs only the record decides.
var rollbackServerSetParams = []string{rollbackTargetCommitParam, rollbackExpectedDigestParam}

// rollbackRecordUnusable says why a record cannot be a rollback target, or
// "" when it can. A record not yet observed is not a known-good state:
// unknown is never treated as healthy.
func rollbackRecordUnusable(rec *deployplan.Record, team, component string) string {
	switch {
	case rec.Tenant != team || rec.Service != component:
		// Reported as not found by the caller of this: a record of another
		// service or workspace must not be distinguishable from an absent one.
		return "other_service"
	case rec.Status != deployplan.RecordSubmitted:
		return "deployment was not submitted"
	case rec.RunResult != "succeeded":
		return "deployment did not succeed"
	case rec.Health != deployplan.HealthHealthy:
		return "deployment was not observed healthy"
	case !deployplan.ValidCommitSHA(rec.CommitSHA):
		return "deployment has no recorded gitops commit"
	case !deployplan.ValidImageDigest(rec.ImageDigest):
		return "deployment has no recorded image digest"
	}
	return ""
}

// prepareRollbackRevision resolves deployment_id into target_commit and
// expected_digest. It runs after tenant access and role are decided, so a
// caller without access never reaches the store. It writes the refusal and
// returns false when the rollback must not go ahead.
func (h *Handlers) prepareRollbackRevision(w http.ResponseWriter, r *http.Request, user *auth.User, op operations.Operation, input map[string]string) bool {
	deny := func(status int, code, msg, audited string) bool {
		h.logAudit(r, audit.Entry{UserID: user.ID, Operation: op.Name, Status: "denied",
			RiskLevel: string(op.RiskLevel), Message: audited, RefusalCode: code,
			Parameters: map[string]string{"team_name": truncate256(input["team_name"]),
				"component_name": truncate256(input["component_name"]), rollbackDeploymentIDParam: truncate256(input[rollbackDeploymentIDParam])}})
		writeErrorCode(w, status, code, msg, nil)
		return false
	}
	id := input[rollbackDeploymentIDParam]
	if !strings.HasPrefix(id, deployplan.RecordIDPrefix) {
		return deny(http.StatusNotFound, codeRollbackDeploymentNotFound, "no such deployment for this service", "denied:"+codeRollbackDeploymentNotFound)
	}
	if h.opts.DeployRecords == nil {
		h.logAudit(r, audit.Entry{UserID: user.ID, Operation: op.Name, Status: "failed", RiskLevel: string(op.RiskLevel),
			Message: "deployment record store unavailable"})
		writeErrorCode(w, http.StatusServiceUnavailable, codeRollbackStoreUnavailable, "the deployment record store is not available", nil)
		return false
	}
	rec, err := h.opts.DeployRecords.GetRecord(r.Context(), id)
	switch {
	case errors.Is(err, deployplan.ErrRecordNotFound):
		return deny(http.StatusNotFound, codeRollbackDeploymentNotFound, "no such deployment for this service", "denied:"+codeRollbackDeploymentNotFound)
	case err != nil:
		slog.Error("rollback-revision: reading the record", "error", err)
		h.logAudit(r, audit.Entry{UserID: user.ID, Operation: op.Name, Status: "failed", RiskLevel: string(op.RiskLevel),
			Message: "deployment record unreadable"})
		writeErrorCode(w, http.StatusServiceUnavailable, codeRollbackStoreUnavailable, "the deployment record store is not available", nil)
		return false
	}
	switch why := rollbackRecordUnusable(rec, input["team_name"], input["component_name"]); why {
	case "":
	case "other_service":
		// The audit row is filed under the caller's team and readable by its
		// members, so it must not name the record's owner either: that is
		// what the 404 hides. The owner goes to the operator log only.
		slog.Warn("rollback-revision: deployment belongs to another service",
			"deployment", rec.ID, "owner", rec.Tenant+"/"+rec.Service, "user", user.ID)
		return deny(http.StatusNotFound, codeRollbackDeploymentNotFound, "no such deployment for this service",
			"denied:"+codeRollbackDeploymentNotFound)
	default:
		return deny(http.StatusConflict, codeRollbackDeploymentNotUsable, "this deployment cannot be rolled back to: "+why, "denied:"+codeRollbackDeploymentNotUsable+": "+why)
	}
	input[rollbackTargetCommitParam] = rec.CommitSHA
	input[rollbackExpectedDigestParam] = rec.ImageDigest
	return true
}
