package workitems

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"regexp"

	"github.com/jackc/pgx/v5"

	"github.com/mctlhq/mctl-api/internal/glovo/dbq"
)

// Glovo work-item bindings (mctl-api#989 task 0, #957 design 6d.2).
//
// The bridge validates wi_/we_ ids as the prefix plus 16-40 alphanumerics
// (internal/bridge/store.go), which the generic hyphenated UUID ids never
// match. A Glovo order therefore gets its own ids, created here on the
// caller's transaction: no work-item tx of its own, no advisory lock.

const glovoIDAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

var (
	glovoWorkItemIDRE = regexp.MustCompile(`^wi_[A-Za-z0-9]{16,40}$`)
	glovoExecutionRE  = regexp.MustCompile(`^we_[A-Za-z0-9]{16,40}$`)
)

// GlovoOriginSurface is the origin surface of a Glovo work item.
const GlovoOriginSurface = "glovo"

func glovoRandID(prefix string) (string, error) {
	const n = 26
	out := make([]byte, 0, n)
	buf := make([]byte, n*2)
	for len(out) < n {
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("workitems: crypto/rand: %w", err)
		}
		for _, b := range buf {
			if b < 248 { // 248 = 62*4: no modulo bias
				out = append(out, glovoIDAlphabet[int(b)%62])
				if len(out) == n {
					break
				}
			}
		}
	}
	return prefix + string(out), nil
}

// GlovoExecutionInput creates the work item and execution of one order.
type GlovoExecutionInput struct {
	Tenant           string
	OwnerPrincipalID string // prn_...
	WorkflowID       string // the Temporal workflow id, stored as engine_ref
	Actor            string // the principal string recorded on the creation event
}

func (in GlovoExecutionInput) validate() error {
	if err := checkIdentity("tenant", in.Tenant); err != nil {
		return err
	}
	if err := checkIdentity("actor", in.Actor); err != nil {
		return err
	}
	if len(in.OwnerPrincipalID) <= len("prn_") || in.OwnerPrincipalID[:4] != "prn_" {
		return invalid("owner_principal_id must be a prn_ id")
	}
	if err := checkIdentity("owner_principal_id", in.OwnerPrincipalID); err != nil {
		return err
	}
	if err := checkText("workflow_id", in.WorkflowID, MaxKeyBytes, true); err != nil {
		return err
	}
	return scanSecrets("workflow_id", in.WorkflowID)
}

// CreateGlovoExecutionTx inserts one work item (owner = the principal, origin
// surface glovo), its creation event and one execution (engine temporal,
// engine_ref = the workflow id, attempt 1, phase Pending) on tx. It writes no
// provenance row: the Glovo runtime role holds INSERT on the three tables only
// (#957 design 6d.1). A rollback of tx leaves nothing behind.
func (s *Store) CreateGlovoExecutionTx(ctx context.Context, tx pgx.Tx, in GlovoExecutionInput) (workItemID, executionID string, err error) {
	if err := in.validate(); err != nil {
		return "", "", err
	}
	if workItemID, err = glovoRandID(WorkItemIDPrefix); err != nil {
		return "", "", err
	}
	if executionID, err = glovoRandID(ExecutionIDPrefix); err != nil {
		return "", "", err
	}
	now := s.now()
	if _, err := tx.Exec(ctx, `INSERT INTO work_items (`+itemColumns+`)
		VALUES ($1,$2,$3,'`+VisibilityPrivate+`',$4,$5,'','`+StateActive+`','','',1,$3,$6,$6,NULL,$7,$8,'')`,
		workItemID, in.Tenant, in.OwnerPrincipalID, GlovoOriginSurface, "Glovo order", now, SchemaVersion, in.OwnerPrincipalID); err != nil {
		return "", "", fmt.Errorf("workitems: create glovo work item: %w", err)
	}
	if err := appendEvent(ctx, tx, workItemID, EventCreated, "", StateActive,
		Mutation{Actor: in.Actor, ActorPrincipalID: in.OwnerPrincipalID, Surface: GlovoOriginSurface}, nil, now); err != nil {
		return "", "", err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO work_item_executions (`+executionColumns+`)
		VALUES ($1,$2,$3,$4,1,'',$5,$6,NULL)`,
		executionID, workItemID, EngineTemporal, in.WorkflowID, PhasePending, now); err != nil {
		return "", "", fmt.Errorf("workitems: create glovo execution: %w", err)
	}
	return workItemID, executionID, nil
}

// ExecutionBindingTx is the #988 Executions collaborator and the #985
// workflow-id source. It answers only for an execution CreateGlovoExecutionTx
// made: a generic (hyphenated) execution id, a work item of another origin
// surface, or an absent id is one ErrNotFound.
func (s *Store) ExecutionBindingTx(ctx context.Context, q dbq.Querier, executionID string) (tenant, ownerPrincipalID, workItemID, workflowID string, err error) {
	if !glovoExecutionRE.MatchString(executionID) {
		return "", "", "", "", ErrNotFound
	}
	err = q.QueryRow(ctx, `SELECT wi.tenant, wi.owner_principal_id, wi.id, e.engine_ref
		FROM work_item_executions e JOIN work_items wi ON wi.id = e.work_item_id
		WHERE e.id = $1 AND wi.origin_surface = $2 AND wi.id LIKE 'wi\_%'`, executionID, GlovoOriginSurface).
		Scan(&tenant, &ownerPrincipalID, &workItemID, &workflowID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", "", "", ErrNotFound
	}
	if err != nil {
		return "", "", "", "", fmt.Errorf("workitems: execution binding: %w", err)
	}
	if !glovoWorkItemIDRE.MatchString(workItemID) {
		return "", "", "", "", ErrNotFound
	}
	return tenant, ownerPrincipalID, workItemID, workflowID, nil
}
