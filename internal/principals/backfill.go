// Copyright 2025 MCTL Authors
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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/mctlhq/mctl-api/internal/auth"
)

// GitHubIDLookup returns the numeric GitHub user id of a login.
type GitHubIDLookup func(ctx context.Context, login string) (int64, error)

// NewGitHubIDLookup asks the GitHub REST API (GET /users/{login}) with the
// token the source yields. A nil token source is allowed: the endpoint is
// public, only the rate limit is lower.
func NewGitHubIDLookup(client *http.Client, baseURL string, token func() (string, error)) GitHubIDLookup {
	if client == nil {
		client = http.DefaultClient
	}
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}
	baseURL = strings.TrimRight(baseURL, "/")
	return func(ctx context.Context, login string) (int64, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/users/"+url.PathEscape(login), nil)
		if err != nil {
			return 0, err
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		if token != nil {
			if t, err := token(); err == nil && t != "" {
				req.Header.Set("Authorization", "Bearer "+t)
			}
		}
		resp, err := client.Do(req)
		if err != nil {
			return 0, fmt.Errorf("github user lookup: %w", err)
		}
		defer resp.Body.Close() //nolint:errcheck
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if resp.StatusCode != http.StatusOK {
			return 0, fmt.Errorf("github user lookup: HTTP %d", resp.StatusCode)
		}
		var u struct {
			Login string `json:"login"`
			ID    int64  `json:"id"`
		}
		if err := json.Unmarshal(body, &u); err != nil || u.ID <= 0 {
			return 0, fmt.Errorf("github user lookup: unexpected response")
		}
		// A login lookup that answers for a different login (a redirect after
		// a rename) is not an answer for this one.
		if !strings.EqualFold(u.Login, login) {
			return 0, fmt.Errorf("github user lookup: %q answers as %q", login, u.Login)
		}
		return u.ID, nil
	}
}

// BackfillResult counts one backfill run.
type BackfillResult struct {
	Logins        int `json:"logins"`
	Known         int `json:"known"`
	Provisioned   int `json:"provisioned"`
	Failed        int `json:"failed"`
	LinksMirrored int `json:"links_mirrored"`
	LinksFailed   int `json:"links_failed"`
}

// Backfill provisions one human principal and one GitHub identity per login
// (gitops tenant members), then mirrors every live surface link whose human
// is now known. It is idempotent: a login that already has a live GitHub
// identity costs no GitHub call and changes nothing, and a link that is
// already mirrored is left as it is.
//
// The source is the gitops member list and nothing else. audit_events.user_id
// in particular is never read: it carries no provider, so a Dex username
// there is indistinguishable from a GitHub login of the same spelling.
func (s *Store) Backfill(ctx context.Context, logins []string, lookup GitHubIDLookup) (BackfillResult, error) {
	var res BackfillResult
	seen := map[string]bool{}
	for _, login := range logins {
		key := strings.ToLower(strings.TrimSpace(login))
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		res.Logins++
		if _, err := s.ResolveGitHubLogin(ctx, login); err == nil {
			res.Known++
			continue
		} else if !errors.Is(err, ErrNotFound) {
			return res, err
		}
		if lookup == nil {
			res.Failed++
			continue
		}
		id, err := lookup(ctx, login)
		if err != nil {
			slog.Warn("principal backfill: github id lookup failed", "login", login, "error", err)
			res.Failed++
			continue
		}
		if _, err := s.Provision(ctx, auth.Identity{
			Provider: auth.ProviderGitHub, Subject: strconv.FormatInt(id, 10), Display: login, Kind: auth.KindHuman,
		}); err != nil {
			if errors.Is(err, auth.ErrIdentityRefused) {
				res.Failed++
				continue
			}
			return res, err
		}
		res.Provisioned++
	}
	var err error
	res.LinksMirrored, res.LinksFailed, err = s.mirrorLiveLinks(ctx)
	return res, err
}

// mirrorLiveLinks copies every live surface link that is not mirrored yet.
// The surface store may be disabled, so a missing table is not an error.
func (s *Store) mirrorLiveLinks(ctx context.Context) (mirrored, failed int, err error) {
	var exists bool
	if err := s.pool.QueryRow(ctx, `SELECT to_regclass('surface_identity_links') IS NOT NULL`).Scan(&exists); err != nil {
		return 0, 0, err
	}
	if !exists {
		return 0, 0, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT l.surface, l.external_id, l.principal FROM surface_identity_links l
		WHERE l.revoked_at IS NULL AND NOT EXISTS (
			SELECT 1 FROM external_identities x
			WHERE x.provider = l.surface AND x.issuer = '' AND x.subject = l.external_id)
		ORDER BY l.surface, l.external_id`)
	if err != nil {
		return 0, 0, err
	}
	type link struct{ surface, externalID, principal string }
	var links []link
	for rows.Next() {
		var l link
		if err := rows.Scan(&l.surface, &l.externalID, &l.principal); err != nil {
			rows.Close()
			return 0, 0, err
		}
		links = append(links, l)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, 0, err
	}
	// One link that cannot be mirrored must not keep every later one
	// unmirrored on every start: it is logged and the rest go on. A link
	// counts only once its transaction committed.
	for _, l := range links {
		var wrote bool
		err = s.withTx(ctx, "principals:mirror:"+l.surface+"|"+l.externalID, func(tx pgx.Tx) error {
			var err error
			wrote, err = s.mirrorLink(ctx, tx, l.surface, l.externalID, l.principal, true)
			return err
		})
		if ctx.Err() != nil {
			return mirrored, failed, ctx.Err()
		}
		if err != nil {
			failed++
			slog.Warn("principal backfill: surface link not mirrored", "surface", l.surface, "principal", l.principal, "error", err)
			continue
		}
		if wrote {
			mirrored++
		}
	}
	if failed > 0 {
		return mirrored, failed, fmt.Errorf("principals: %d surface link(s) not mirrored", failed)
	}
	return mirrored, 0, nil
}
