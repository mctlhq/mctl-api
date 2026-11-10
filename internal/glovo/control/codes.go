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

package control

import (
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/mctlhq/mctl-api/internal/bridge"
	"github.com/mctlhq/mctl-api/internal/glovo"
)

// RefusalCodes is the closed set of codes the control routes send
// (mctl-api#985 design 2b). Every member is a row of the #959 glovo.Code enum
// and of #957 design 4.1; there is no new vocabulary. The internal reason goes
// to audit only.
var RefusalCodes = []glovo.Code{
	glovo.CodeNotAuthorized, glovo.CodeNotReady, glovo.CodeUnavailable, glovo.CodeTenantBusy,
	glovo.CodeInvalidRequest, glovo.CodeNotFound, glovo.CodeApprovalInvalid, glovo.CodeApprovalExpired,
	glovo.CodeApprovalReplayed, glovo.CodeIntentMismatch, glovo.CodeBasketChanged, glovo.CodeNoTenant,
	glovo.CodeNoConnection, glovo.CodeConnectionRevoked, glovo.CodeConnectionExpired, glovo.CodeStaleInstall,
	glovo.CodeInvalidTransition, glovo.CodeRateLimited,
}

// Refusal maps any error of a control call to a member of RefusalCodes. A
// typed Glovo refusal keeps its code when the code is in the set; a lock
// timeout is tenant_busy; a bridge read-level refusal is not_ready; everything
// else, including a failed read, is unavailable and never a refusal that
// could read as "no". The full error text is the internal reason.
func Refusal(err error) *glovo.Error {
	if err == nil {
		return nil
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "55P03" {
		return glovo.Refuse(glovo.CodeTenantBusy)
	}
	if errors.Is(err, bridge.ErrReadUnavailable) {
		return glovo.Refuse(glovo.CodeNotReady)
	}
	ge := glovo.AsError(err)
	for _, c := range RefusalCodes {
		if c == ge.Code {
			return ge
		}
	}
	return glovo.Refuse(glovo.CodeUnavailable)
}

// refuse wraps a code with an internal reason for audit; Refusal recovers the
// code and the reason stays in the error text.
func refuse(c glovo.Code, reason string) error {
	return &reasoned{err: glovo.Refuse(c), reason: reason}
}

type reasoned struct {
	err    *glovo.Error
	reason string
}

func (r *reasoned) Error() string { return r.err.Error() + ": " + r.reason }
func (r *reasoned) Unwrap() error { return r.err }

// Reason is the internal reason of err for audit, or its text.
func Reason(err error) string {
	var r *reasoned
	if errors.As(err, &r) {
		return r.reason
	}
	if err == nil {
		return ""
	}
	return err.Error()
}

// unavailable is the answer for a failed read or write that is not a typed
// refusal: unavailable, except that a lock timeout stays a lock timeout (so
// Refusal maps it to tenant_busy) and a bridge read-level refusal stays one.
func unavailable(reason string, err error) error {
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "55P03" || errors.Is(err, bridge.ErrReadUnavailable) {
		return fmt.Errorf("control: %s: %w", reason, err)
	}
	return refuse(glovo.CodeUnavailable, reason+": "+err.Error())
}
