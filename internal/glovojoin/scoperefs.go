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
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/dbq"
)

// ScopeRefTTL is the longest life of a scope ref (design 2b).
const ScopeRefTTL = 5 * time.Minute

var scopeRefRE = regexp.MustCompile(`^gsc_[A-Za-z0-9_-]{32}$`)

// ScopeRefs is the server-side store of the scope refs the facade resolves once
// per tool call (design 2b). A ref is a reference, not an authority: a handler
// never reads tenant or owner from the row, it only requires the row to agree
// with what it re-derived from the verified subject.
type ScopeRefs struct {
	DB  dbq.Querier
	Now func() time.Time
}

func (s *ScopeRefs) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Issue mints a ref bound to the subject: principal, tenant, install id and
// revision, and the refresh family of the team grant. The plaintext is returned
// once; only sha256(ref) is stored. expires_at is min(now + 5 min, token exp).
func (s *ScopeRefs) Issue(ctx context.Context, sub Subject) (ref string, expires time.Time, err error) {
	if s == nil || s.DB == nil {
		return "", time.Time{}, refusal(glovo.CodeNotReady, "not_ready:scope_refs")
	}
	created := s.now().UTC().Truncate(time.Millisecond)
	expires = created.Add(ScopeRefTTL)
	if sub.ExpiresAt.Before(expires) {
		expires = sub.ExpiresAt.UTC().Truncate(time.Millisecond)
	}
	if !expires.After(created) {
		return "", time.Time{}, unauthenticated("subject_token_invalid:exp")
	}
	var raw [24]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", time.Time{}, fmt.Errorf("glovojoin: scope ref entropy: %w: %w", glovo.Refuse(glovo.CodeUnavailable), err)
	}
	ref = "gsc_" + base64.RawURLEncoding.EncodeToString(raw[:])
	_, err = s.DB.Exec(ctx, `INSERT INTO glovo.join_scope_refs
 (ref_hash, principal_id, tenant, install_id, install_revision, grant_family_id, created_at, expires_at)
 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		refHash(ref), sub.PrincipalID, sub.Tenant, sub.InstallID, sub.InstallRevision, sub.FamilyID, created, expires)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("glovojoin: store scope ref: %w: %w", glovo.Refuse(glovo.CodeUnavailable), err)
	}
	return ref, expires, nil
}

// Validate checks ref against the freshly verified subject. An unknown,
// malformed, expired or foreign ref, or one bound to another principal, tenant,
// install or grant family, is 403 not_authorized with no distinction on the
// wire; a ref whose install revision is no longer current is 403
// stale_install; a failed read is unavailable, never "unknown".
func (s *ScopeRefs) Validate(ctx context.Context, ref string, sub Subject) *Refusal {
	if s == nil || s.DB == nil {
		return refusal(glovo.CodeNotReady, "not_ready:scope_refs")
	}
	bad := func() *Refusal { return refusal(glovo.CodeNotAuthorized, "scope_ref_invalid") }
	if !scopeRefRE.MatchString(ref) {
		return bad()
	}
	var principal, tenant, installID, family string
	var rev int64
	err := s.DB.QueryRow(ctx, `SELECT principal_id, tenant, install_id, install_revision, grant_family_id
 FROM glovo.join_scope_refs WHERE ref_hash = $1 AND expires_at > $2`, refHash(ref), s.now().UTC()).
		Scan(&principal, &tenant, &installID, &rev, &family)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return bad()
	case err != nil:
		return &Refusal{Err: glovo.Refuse(glovo.CodeUnavailable), Reason: "dependency_unavailable:scope_refs"}
	}
	if principal != sub.PrincipalID || tenant != sub.Tenant || family != sub.FamilyID || installID != sub.InstallID {
		return bad()
	}
	if rev != sub.InstallRevision {
		return refusal(glovo.CodeStaleInstall, "scope_ref_stale")
	}
	return nil
}

// Sweep deletes at most limit expired rows. Expired rows are refused on read
// regardless of the sweep; this only bounds the table.
func (s *ScopeRefs) Sweep(ctx context.Context, limit int) (int64, error) {
	tag, err := s.DB.Exec(ctx, `DELETE FROM glovo.join_scope_refs WHERE ref_hash IN
 (SELECT ref_hash FROM glovo.join_scope_refs WHERE expires_at <= $1 LIMIT $2)`, s.now().UTC(), limit)
	if err != nil {
		return 0, fmt.Errorf("glovojoin: sweep scope refs: %w", err)
	}
	return tag.RowsAffected(), nil
}

// refHash is the stored form of a ref.
func refHash(ref string) string {
	sum := sha256.Sum256([]byte(ref))
	return hex.EncodeToString(sum[:])
}
