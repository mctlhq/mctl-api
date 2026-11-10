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

package glovojoin

import (
	"context"
	"errors"
	"regexp"

	"github.com/jackc/pgx/v5"

	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/dbq"
)

var orderRefRE = regexp.MustCompile(`^ordr_[A-Za-z0-9]{16,40}$`)

// ControlStartTx reads the workflow id and run id of the order's workflow-start
// record (mctl-api#957 design 6d.2, 6d.4). It is a read on the caller's
// querier, a pool or the caller's pgx.Tx, and never begins, commits or locks.
// The run id is empty until the workflow has started, and an empty run id is
// valid: the result signal then goes to the workflow id's current run. A
// malformed ref is invalid_request, an absent row is not_found and any other
// failure is unavailable: a failed read is never an empty answer.
func ControlStartTx(ctx context.Context, q dbq.Querier, orderRef string) (workflowID, runID string, err error) {
	if !orderRefRE.MatchString(orderRef) {
		return "", "", glovo.Refuse(glovo.CodeInvalidRequest)
	}
	err = q.QueryRow(ctx, `SELECT workflow_id, started_run_id FROM glovo.control_starts WHERE order_ref = $1`, orderRef).Scan(&workflowID, &runID)
	switch {
	case err == nil:
		return workflowID, runID, nil
	case errors.Is(err, pgx.ErrNoRows):
		return "", "", glovo.Refuse(glovo.CodeNotFound)
	default:
		return "", "", glovo.Refuse(glovo.CodeUnavailable)
	}
}
