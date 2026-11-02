package workitems

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/mctlhq/mctl-api/internal/executionprovenance"
)

// ErrProvenanceAbsent means the store was read and holds no provenance for
// the execution id. A read failure is never this error.
var ErrProvenanceAbsent = errors.New("execution provenance absent")

// Provenance is the stored execution_attempt_v1 record of one execution.
// AttachedBy and AttachedByPrincipal record who chose engine and engine_ref;
// they are an audit trail, not an eligibility decision.
type Provenance struct {
	ExecutionID         string    `json:"execution_id"`
	ContractVersion     string    `json:"contract_version"`
	AttemptID           string    `json:"attempt_id"`
	LineageRoot         string    `json:"lineage_root"`
	Engine              string    `json:"engine"`
	EngineRun           string    `json:"engine_run"`
	ParentExecutionID   string    `json:"parent_execution_id"`
	RootExecutionID     string    `json:"root_execution_id"`
	AttachedBy          string    `json:"attached_by"`
	AttachedByPrincipal string    `json:"attached_by_principal"`
	RecordedAt          time.Time `json:"recorded_at"`
}

const provenanceColumns = `execution_id, contract_version, attempt_id, lineage_root, engine, engine_run,
	parent_execution_id, root_execution_id, attached_by, attached_by_principal, recorded_at`

// maxLineageWalk bounds the legacy root walk so a corrupt cycle cannot loop.
const maxLineageWalk = 10000

// rootOf is the root_execution_id of a new execution resumed from parent.
// Every input is a stored row: the parent's provenance, else (a parent created
// before provenance existed) a walk of stored resumed_from_execution_id.
func rootOf(ctx context.Context, tx pgx.Tx, parent string) (string, error) {
	var root string
	err := tx.QueryRow(ctx, `SELECT root_execution_id FROM execution_provenance WHERE execution_id=$1`, parent).Scan(&root)
	if err == nil {
		return root, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("workitems: read parent provenance: %w", err)
	}
	cur := parent
	for i := 0; i < maxLineageWalk; i++ {
		var from string
		if err := tx.QueryRow(ctx, `SELECT resumed_from_execution_id FROM work_item_executions WHERE id=$1`, cur).Scan(&from); err != nil {
			return "", fmt.Errorf("workitems: walk lineage at %s: %w", cur, err)
		}
		if from == "" {
			return cur, nil
		}
		cur = from
	}
	return "", fmt.Errorf("workitems: lineage of %s exceeds %d links", parent, maxLineageWalk)
}

func insertProvenance(ctx context.Context, tx pgx.Tx, e *Execution, from string, m Mutation, now time.Time) error {
	root := e.ID
	if from != "" {
		var err error
		if root, err = rootOf(ctx, tx, from); err != nil {
			return err
		}
	}
	_, err := tx.Exec(ctx, `INSERT INTO execution_provenance (`+provenanceColumns+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		e.ID, executionprovenance.ContractVersion,
		executionprovenance.AttemptID(e.Engine, e.EngineRef), executionprovenance.LineageRoot(root),
		e.Engine, executionprovenance.EngineRun(e.EngineRef), from, root,
		m.Actor, m.ActorPrincipalID, now)
	if err != nil {
		return fmt.Errorf("workitems: insert execution provenance: %w", err)
	}
	return nil
}

func validProvenance(p *Provenance) error {
	if p.ContractVersion != executionprovenance.ContractVersion ||
		!executionprovenance.AttemptIDRE.MatchString(p.AttemptID) ||
		!executionprovenance.LineageRootRE.MatchString(p.LineageRoot) {
		return fmt.Errorf("workitems: stored provenance of %s fails validation", p.ExecutionID)
	}
	return nil
}

// ExecutionProvenance returns the stored record for a we_ execution id,
// ErrProvenanceAbsent when none exists, or a non-absent error when the store
// cannot be read or the stored row fails re-validation.
func (s *Store) ExecutionProvenance(ctx context.Context, executionID string) (*Provenance, error) {
	var p Provenance
	err := s.pool.QueryRow(ctx, `SELECT `+provenanceColumns+` FROM execution_provenance WHERE execution_id=$1`, executionID).
		Scan(&p.ExecutionID, &p.ContractVersion, &p.AttemptID, &p.LineageRoot, &p.Engine, &p.EngineRun,
			&p.ParentExecutionID, &p.RootExecutionID, &p.AttachedBy, &p.AttachedByPrincipal, &p.RecordedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: %s", ErrProvenanceAbsent, executionID)
	}
	if err != nil {
		return nil, fmt.Errorf("workitems: read provenance: %w", err)
	}
	if err := validProvenance(&p); err != nil {
		return nil, err
	}
	p.RecordedAt = p.RecordedAt.UTC()
	return &p, nil
}

// LineageAttempts reports, for each requested attempt id, whether some
// recorded execution of lineageRoot has that attempt.
func (s *Store) LineageAttempts(ctx context.Context, lineageRoot string, attemptIDs []string) (map[string]bool, error) {
	out := make(map[string]bool, len(attemptIDs))
	if len(attemptIDs) == 0 {
		return out, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT DISTINCT attempt_id FROM execution_provenance
		WHERE lineage_root=$1 AND attempt_id = ANY($2)`, lineageRoot, attemptIDs)
	if err != nil {
		return nil, fmt.Errorf("workitems: read lineage attempts: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("workitems: scan lineage attempts: %w", err)
		}
		out[id] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("workitems: read lineage attempts: %w", err)
	}
	return out, nil
}
