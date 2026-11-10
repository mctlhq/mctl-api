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

package bridge

import (
	"context"
	"errors"
	"strconv"

	"github.com/mctlhq/mctl-api/internal/glovo"
)

// LiveConnectionReader is the slice of the #959 store the checker uses.
type LiveConnectionReader interface {
	LiveConnection(ctx context.Context, owner glovo.Owner) (*glovo.Connection, error)
}

// GlovoConnectionChecker is the ConnectionChecker over the #959 live
// connection read. Both stores share one database, so there is no
// cross-database window.
type GlovoConnectionChecker struct{ Store LiveConnectionReader }

// Live maps the typed #959 answers: no_connection, connection_revoked and
// connection_expired become *NotLiveError; anything else is an error.
func (g GlovoConnectionChecker) Live(ctx context.Context, tenant, principalID string) (LiveConnection, error) {
	if g.Store == nil {
		return LiveConnection{}, errors.New("no glovo store")
	}
	c, err := g.Store.LiveConnection(ctx, glovo.Owner{TenantID: tenant, PrincipalID: principalID})
	if err != nil {
		for _, code := range []glovo.Code{glovo.CodeNoConnection, glovo.CodeConnectionRevoked, glovo.CodeConnectionExpired} {
			if errors.Is(err, glovo.Refuse(code)) {
				return LiveConnection{}, &NotLiveError{State: string(code)}
			}
		}
		return LiveConnection{}, err
	}
	return LiveConnection{ConnectionRef: c.ConnectionID, InstallRevision: strconv.FormatInt(c.InstallRevision, 10)}, nil
}
