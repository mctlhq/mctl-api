package humaninput

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const ledgerSchema = `
CREATE TABLE IF NOT EXISTS human_input_deliveries (
    request_id            TEXT PRIMARY KEY,
    request_hash          TEXT NOT NULL,
    workflow_id           TEXT NOT NULL,
    run_id                TEXT NOT NULL,
    respondent            TEXT NOT NULL,
    surface               TEXT NOT NULL,
    value_hash            TEXT NOT NULL,
    value                 TEXT,
    received_at           TIMESTAMPTZ NOT NULL,
    state                 TEXT NOT NULL,
    baseline_resume_count INTEGER NOT NULL,
    attempts              INTEGER NOT NULL DEFAULT 0,
    updated_at            TIMESTAMPTZ NOT NULL
);
`

const deliveryColumns = `request_id, request_hash, workflow_id, run_id, respondent, surface,
	value_hash, value, received_at, state, baseline_resume_count, attempts, updated_at`

// PostgresLedger is the Ledger mctl-api runs with. The request_id primary
// key is what makes the first claim win across replicas.
type PostgresLedger struct {
	pool *pgxpool.Pool
}

// NewPostgresLedger connects and creates the table if needed.
func NewPostgresLedger(ctx context.Context, connStr string) (*PostgresLedger, error) {
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		return nil, fmt.Errorf("human-input ledger: connect: %w", err)
	}
	if _, err := pool.Exec(ctx, ledgerSchema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("human-input ledger: create schema: %w", err)
	}
	slog.Info("human-input ledger initialized")
	return &PostgresLedger{pool: pool}, nil
}

// Close releases the pool.
func (p *PostgresLedger) Close() { p.pool.Close() }

func scanDelivery(row pgx.Row) (*Delivery, error) {
	var d Delivery
	var value *string
	if err := row.Scan(&d.RequestID, &d.RequestHash, &d.WorkflowID, &d.RunID, &d.Respondent, &d.Surface,
		&d.ValueHash, &value, &d.ReceivedAt, &d.State, &d.BaselineResumeCount, &d.Attempts, &d.UpdatedAt); err != nil {
		return nil, err
	}
	if value != nil {
		d.Value = []byte(*value)
	}
	d.ReceivedAt = d.ReceivedAt.UTC()
	d.UpdatedAt = d.UpdatedAt.UTC()
	return &d, nil
}

func (p *PostgresLedger) Get(ctx context.Context, requestID string) (*Delivery, error) {
	d, err := scanDelivery(p.pool.QueryRow(ctx,
		`SELECT `+deliveryColumns+` FROM human_input_deliveries WHERE request_id=$1`, requestID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("human-input ledger: get: %w", err)
	}
	return d, nil
}

// Claim is one statement: insert, or take over a rejected row. The
// conditional DO UPDATE returns no row when the existing one is pending or
// accepted, which is how the loser of a race finds out.
func (p *PostgresLedger) Claim(ctx context.Context, d Delivery) (*Delivery, bool, error) {
	claimed, err := scanDelivery(p.pool.QueryRow(ctx, `
		INSERT INTO human_input_deliveries (`+deliveryColumns+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'`+DeliveryPending+`',$10,0,now())
		ON CONFLICT (request_id) DO UPDATE SET
		    request_hash=EXCLUDED.request_hash, workflow_id=EXCLUDED.workflow_id,
		    run_id=EXCLUDED.run_id, respondent=EXCLUDED.respondent, surface=EXCLUDED.surface,
		    value_hash=EXCLUDED.value_hash, value=EXCLUDED.value, received_at=EXCLUDED.received_at,
		    state=EXCLUDED.state, baseline_resume_count=EXCLUDED.baseline_resume_count,
		    attempts=0, updated_at=now()
		WHERE human_input_deliveries.state='`+DeliveryRejected+`'
		RETURNING `+deliveryColumns,
		d.RequestID, d.RequestHash, d.WorkflowID, d.RunID, d.Respondent, d.Surface,
		d.ValueHash, string(d.Value), d.ReceivedAt, d.BaselineResumeCount))
	if err == nil {
		return claimed, true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, false, fmt.Errorf("human-input ledger: claim: %w", err)
	}
	cur, err := p.Get(ctx, d.RequestID)
	if err != nil {
		return nil, false, err
	}
	if cur == nil {
		// Deleted between the two statements; nothing deletes rows, so
		// this is not expected. Report it rather than claim blindly.
		return nil, false, fmt.Errorf("human-input ledger: claim: row for %s vanished", d.RequestID)
	}
	return cur, false, nil
}

func (p *PostgresLedger) NoteAttempt(ctx context.Context, requestID string) error {
	tag, err := p.pool.Exec(ctx, `UPDATE human_input_deliveries SET attempts=attempts+1, updated_at=now()
		WHERE request_id=$1 AND state='`+DeliveryPending+`'`, requestID)
	if err != nil {
		return fmt.Errorf("human-input ledger: note attempt: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrDeliveryNotPending
	}
	return nil
}

func (p *PostgresLedger) Resolve(ctx context.Context, d Delivery, state string) error {
	tag, err := p.pool.Exec(ctx, `UPDATE human_input_deliveries SET state=$2, value=NULL, updated_at=now()
		WHERE request_id=$1 AND state='`+DeliveryPending+`'
		  AND respondent=$3 AND value_hash=$4 AND request_hash=$5`,
		d.RequestID, state, d.Respondent, d.ValueHash, d.RequestHash)
	if err != nil {
		return fmt.Errorf("human-input ledger: resolve: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrDeliveryNotPending
	}
	return nil
}
