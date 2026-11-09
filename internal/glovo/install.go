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
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/mctlhq/mctl-api/internal/glovo/dbq"
)

const installCols = `install_id, tenant_id, install_revision, state, installed_by, created_at, updated_at, version`

func scanInstall(r scanner) (*Install, error) {
	var i Install
	var state string
	if err := r.Scan(&i.InstallID, &i.TenantID, &i.InstallRevision, &state, &i.InstalledBy, &i.CreatedAt, &i.UpdatedAt, &i.Version); err != nil {
		return nil, err
	}
	i.State = InstallState(state)
	return &i, nil
}

func installAudit(i *Install, actor Actor, event, from, reason string) AuditEvent {
	return AuditEvent{
		TenantID: i.TenantID, ActorPrincipalID: actor.PrincipalID, ActorKind: actor.Kind,
		EntityKind: "install", EntityID: i.InstallID, Event: event,
		FromState: from, ToState: string(i.State), InstallRevision: i.InstallRevision, ReasonCode: reason,
	}
}

func validTenant(t string) error {
	if t == "" || len(t) > 253 {
		return refuse(CodeInvalidRequest)
	}
	return nil
}

// lockInstallRow reads the tenant's install row FOR UPDATE; absent is nil.
func lockInstallRow(ctx context.Context, q dbq.Querier, tenant string) (*Install, error) {
	i, err := scanInstall(q.QueryRow(ctx, `SELECT `+installCols+` FROM glovo.glovo_installs WHERE tenant_id = $1 FOR UPDATE`, tenant))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("glovo: read install: %w", err)
	}
	return i, nil
}

// Install creates the tenant's install at revision 1 (the id and revision are
// minted here, never chosen by the caller). It is idempotent for an installed
// tenant; an uninstalled one is brought back with Reinstall.
func (s *Store) Install(ctx context.Context, tenantID string, actor Actor) (*Install, error) {
	if err := validTenant(tenantID); err != nil {
		return nil, err
	}
	if err := actor.validate(); err != nil {
		return nil, err
	}
	var out *Install
	err := s.withTx(ctx, func(tx pgx.Tx) error {
		if err := s.withLocks(ctx, tx, tenantID, "", lockExclusive); err != nil {
			return err
		}
		cur, err := lockInstallRow(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		if cur != nil {
			if cur.State != InstallInstalled {
				return refuse(CodeInvalidTransition)
			}
			out = cur
			return nil
		}
		now := s.now()
		id, err := newPrefixedID(prefixInstall, now)
		if err != nil {
			return err
		}
		i, err := scanInstall(tx.QueryRow(ctx, `INSERT INTO glovo.glovo_installs
  (install_id, tenant_id, install_revision, state, installed_by, created_at, updated_at, version)
  VALUES ($1, $2, 1, 'installed', $3, $4, $4, 1) RETURNING `+installCols, id, tenantID, actor.PrincipalID, now))
		if err != nil {
			return fmt.Errorf("glovo: insert install: %w", err)
		}
		if err := s.appendAudit(ctx, tx, installAudit(i, actor, "install_created", "", "")); err != nil {
			return err
		}
		out = i
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetInstall returns the tenant's current install. An absent row and an
// uninstalled one are both no_install. It takes no lock and runs one
// statement.
func (s *Store) GetInstall(ctx context.Context, tenantID string) (*Install, error) {
	if err := validTenant(tenantID); err != nil {
		return nil, err
	}
	i, err := scanInstall(s.pool.QueryRow(ctx, `SELECT `+installCols+` FROM glovo.glovo_installs WHERE tenant_id = $1`, tenantID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, refuse(CodeNoInstall)
	}
	if err != nil {
		return nil, fmt.Errorf("glovo: read install: %w", err)
	}
	if i.State != InstallInstalled {
		return nil, refuse(CodeNoInstall)
	}
	return i, nil
}

// liveConnectionIDs returns the tenant's live connections bound to a revision
// below `below`, locked FOR UPDATE, in id order.
func liveConnectionIDs(ctx context.Context, q dbq.Querier, tenant string, below int64) ([]string, error) {
	rows, err := q.Query(ctx, `SELECT connection_id FROM glovo.glovo_connections
 WHERE tenant_id = $1 AND install_revision < $2 AND state IN ('pending_handoff','pending_provider','active')
 ORDER BY connection_id FOR UPDATE`, tenant, below)
	if err != nil {
		return nil, fmt.Errorf("glovo: list live connections: %w", err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("glovo: scan connection id: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// RevokeInstall uninstalls the tenant and, in the same transaction, ends every
// live connection of the tenant with reason install_revoked. It returns the
// connections it ended.
func (s *Store) RevokeInstall(ctx context.Context, tenantID string, actor Actor, reason string, expectedRevision int64) (*Install, []Connection, error) {
	if err := validTenant(tenantID); err != nil {
		return nil, nil, err
	}
	if err := actor.validate(); err != nil {
		return nil, nil, err
	}
	if reason != "" && !validReason(reason) {
		return nil, nil, refuse(CodeInvalidRequest)
	}
	var inst *Install
	var ended []Connection
	err := s.withTx(ctx, func(tx pgx.Tx) error {
		if err := s.withLocks(ctx, tx, tenantID, "", lockExclusive); err != nil {
			return err
		}
		cur, err := lockInstallRow(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		if cur == nil || cur.State != InstallInstalled {
			return refuse(CodeNoInstall)
		}
		if cur.InstallRevision != expectedRevision {
			return refuse(CodeStaleInstall)
		}
		now := s.now()
		inst, err = scanInstall(tx.QueryRow(ctx, `UPDATE glovo.glovo_installs
  SET state = 'uninstalled', updated_at = $2, version = version + 1
  WHERE install_id = $1 RETURNING `+installCols, cur.InstallID, now))
		if err != nil {
			return fmt.Errorf("glovo: revoke install: %w", err)
		}
		if err := s.appendAudit(ctx, tx, installAudit(inst, actor, "install_revoked", string(InstallInstalled), reason)); err != nil {
			return err
		}
		ids, err := liveConnectionIDs(ctx, tx, tenantID, inst.InstallRevision+1)
		if err != nil {
			return err
		}
		ended, err = s.endConnection(ctx, tx, ids, Revoked, ReasonInstallRevoked, actor)
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	return inst, ended, nil
}

// Reinstall raises the install revision by one (bringing an uninstalled
// install back to installed) and, in the same transaction, ends every live
// connection bound to an older revision with reason install_reinstalled.
func (s *Store) Reinstall(ctx context.Context, tenantID string, actor Actor, expectedRevision int64) (*Install, []Connection, error) {
	if err := validTenant(tenantID); err != nil {
		return nil, nil, err
	}
	if err := actor.validate(); err != nil {
		return nil, nil, err
	}
	var inst *Install
	var ended []Connection
	err := s.withTx(ctx, func(tx pgx.Tx) error {
		if err := s.withLocks(ctx, tx, tenantID, "", lockExclusive); err != nil {
			return err
		}
		cur, err := lockInstallRow(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		if cur == nil {
			return refuse(CodeNoInstall)
		}
		if cur.InstallRevision != expectedRevision {
			return refuse(CodeStaleInstall)
		}
		now := s.now()
		inst, err = scanInstall(tx.QueryRow(ctx, `UPDATE glovo.glovo_installs
  SET state = 'installed', install_revision = install_revision + 1, updated_at = $2, version = version + 1
  WHERE install_id = $1 RETURNING `+installCols, cur.InstallID, now))
		if err != nil {
			return fmt.Errorf("glovo: reinstall: %w", err)
		}
		if err := s.appendAudit(ctx, tx, installAudit(inst, actor, "install_reinstalled", string(cur.State), "")); err != nil {
			return err
		}
		ids, err := liveConnectionIDs(ctx, tx, tenantID, inst.InstallRevision)
		if err != nil {
			return err
		}
		ended, err = s.endConnection(ctx, tx, ids, Revoked, ReasonInstallReinstalled, actor)
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	return inst, ended, nil
}
