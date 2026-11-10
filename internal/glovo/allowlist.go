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

package glovo

import (
	"context"
	"fmt"
)

// AllowlistAdd puts a principal on a tenant's pilot allowlist. Both a tenant
// and a prn_ principal are required: there is no tenant-wide or wildcard
// entry. Adding an existing row is a no-op. The table is #959's; the runtime
// role holds INSERT on it, and the caller has already authorized an admin.
func (s *Store) AllowlistAdd(ctx context.Context, tenantID, principalID, addedBy string) error {
	if err := (Owner{TenantID: tenantID, PrincipalID: principalID}).validate(); err != nil {
		return err
	}
	if addedBy == "" {
		return refuse(CodeInvalidRequest)
	}
	if _, err := s.pool.Exec(ctx, `INSERT INTO glovo.glovo_pilot_allowlist (tenant_id, principal_id, added_by, added_at)
 VALUES ($1, $2, $3, $4) ON CONFLICT (tenant_id, principal_id) DO NOTHING`, tenantID, principalID, addedBy, s.clock().UTC()); err != nil {
		return fmt.Errorf("glovo: add allowlist: %w", err)
	}
	return nil
}

// AllowlistRemove takes a principal off a tenant's pilot allowlist. It takes
// effect on the principal's next resource request and next refresh.
func (s *Store) AllowlistRemove(ctx context.Context, tenantID, principalID string) error {
	if err := (Owner{TenantID: tenantID, PrincipalID: principalID}).validate(); err != nil {
		return err
	}
	if _, err := s.pool.Exec(ctx, `DELETE FROM glovo.glovo_pilot_allowlist WHERE tenant_id = $1 AND principal_id = $2`, tenantID, principalID); err != nil {
		return fmt.Errorf("glovo: remove allowlist: %w", err)
	}
	return nil
}
