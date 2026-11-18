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

package principals

import (
	"context"

	"github.com/mctlhq/mctl-api/internal/glovoconsent"
)

// IdentityFacts implements glovoconsent.IdentitySource: the live facts the
// Glovo link preview masks into a label. A missing principal or a failed read
// is an error, never empty facts; revoked identities are left out.
func (s *Store) IdentityFacts(ctx context.Context, principalID string) (glovoconsent.IdentityFacts, error) {
	p, err := s.Get(ctx, principalID)
	if err != nil {
		return glovoconsent.IdentityFacts{}, err
	}
	ids, err := s.Identities(ctx, principalID)
	if err != nil {
		return glovoconsent.IdentityFacts{}, err
	}
	f := glovoconsent.IdentityFacts{DisplayName: p.DisplayName}
	for i := range ids {
		x := &ids[i]
		if x.RevokedAt == nil {
			f.Identities = append(f.Identities, glovoconsent.IdentityFact{Provider: x.Provider, Display: x.Display})
		}
	}
	return f, nil
}
