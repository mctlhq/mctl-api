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

package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/secretscan"
)

// openClawIdentityFileAllowlist fixes the set of identity override filenames a
// tenant can save / delete. Matches mctl-openclaw's hard-coded identity files.
// Enforced in both the HTTP handler and the workflow template as
// defense-in-depth.
var openClawIdentityFileAllowlist = map[string]struct{}{
	"AGENTS.md":   {},
	"SOUL.md":     {},
	"IDENTITY.md": {},
	"USER.md":     {},
	"TOOLS.md":    {},
}

// validateOpenClawIdentityFileName returns nil when fileName is in the fixed
// identity allowlist. Rejects anything else — no kebab-case sluggification,
// the filename is kept verbatim (including .md).
func validateOpenClawIdentityFileName(fileName string) error {
	if fileName == "" {
		return errors.New("file_name is required")
	}
	if _, ok := openClawIdentityFileAllowlist[fileName]; !ok {
		return errors.New("file_name must be one of AGENTS.md, SOUL.md, IDENTITY.md, USER.md, TOOLS.md")
	}
	return nil
}

type openClawIdentitySaveRequest struct {
	FileName string `json:"file_name"`
	Content  string `json:"content"`
}

// ListOpenClawIdentity returns the identity override files backed up in gitops
// for a team. Empty list if the tenant has never saved an override — the
// runtime falls back to the image-shipped defaults.
// GET /api/v1/openclaw/{team}/identity
func (h *Handlers) ListOpenClawIdentity(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	team := strings.TrimSpace(chi.URLParam(r, "team"))
	if _, denied := h.requireOpenClawOwner(w, r, user, team); denied {
		return
	}

	files, err := h.opts.GitReader.ListOpenClawIdentity(team)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list identity files: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"team":     team,
		"identity": files,
	})
}

// GetOpenClawIdentity returns the raw content of a single identity override
// file. fileName must be in the allowlist or the handler returns 400.
// GET /api/v1/openclaw/{team}/identity/{name}
func (h *Handlers) GetOpenClawIdentity(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	team := strings.TrimSpace(chi.URLParam(r, "team"))
	if _, denied := h.requireOpenClawOwner(w, r, user, team); denied {
		return
	}

	name := strings.TrimSpace(chi.URLParam(r, "name"))
	if err := validateOpenClawIdentityFileName(name); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	content, err := h.opts.GitReader.ReadOpenClawIdentity(team, name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			writeError(w, http.StatusNotFound, "identity file not found: "+name)
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to read identity file: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"team":    team,
		"name":    name,
		"content": content,
	})
}

// SaveOpenClawIdentity submits the openclaw-identity-save workflow which
// writes the identity override to the gitops repo. Same quota / secret-scan /
// rate-limit gates as SaveOpenClawSkill — rate limit budget is shared.
// POST /api/v1/openclaw/{team}/identity (body: {file_name, content})
func (h *Handlers) SaveOpenClawIdentity(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	team := strings.TrimSpace(chi.URLParam(r, "team"))

	// Ownership gate runs before any body parse to avoid leaking probe signals.
	if _, denied := h.requireOpenClawOwner(w, r, user, team); denied {
		return
	}

	perFileCap := h.openClawQuota.MaxPerSkillBytes
	r.Body = http.MaxBytesReader(w, r.Body, int64(perFileCap)+4*1024)
	var req openClawIdentitySaveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("request body exceeds %d bytes", perFileCap))
			return
		}
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	req.FileName = strings.TrimSpace(req.FileName)
	if err := validateOpenClawIdentityFileName(req.FileName); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(req.Content) == "" {
		writeError(w, http.StatusBadRequest, "content must not be empty")
		return
	}
	if len(req.Content) > perFileCap {
		writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("content exceeds %d bytes", perFileCap))
		return
	}

	if pattern, found := secretscan.Scan([]byte(req.Content)); found {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("content appears to contain a secret (matched pattern: %s); skills/identity files must not embed credentials — use mctl_* runtime tools instead", pattern))
		return
	}

	// Enforce identity caps — five fixed filenames means the file-count cap is
	// essentially redundant with the allowlist, but we still sum bytes so a
	// user can't push all five files to the per-file cap and then starve the
	// ConfigMap headroom.
	existing, listErr := h.opts.GitReader.ListOpenClawIdentity(team)
	if listErr != nil {
		writeError(w, http.StatusInternalServerError, "failed to read existing identity files for quota check: "+listErr.Error())
		return
	}
	var existingBytes int
	var updatingExisting bool
	for _, f := range existing {
		if f.Name == req.FileName {
			updatingExisting = true
			continue
		}
		existingBytes += int(f.Size)
	}
	if !updatingExisting && len(existing) >= h.openClawQuota.MaxIdentityFilesPerTenant {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("identity file count limit reached (%d of %d used for team %q); delete an override with mctl_delete_openclaw_identity before saving a new one", len(existing), h.openClawQuota.MaxIdentityFilesPerTenant, team))
		return
	}
	projected := existingBytes + len(req.Content) + len(req.FileName)
	if projected > h.openClawQuota.MaxIdentityTotalBytes {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("per-tenant identity ConfigMap size limit would be exceeded (current %d bytes + new %d bytes > cap %d bytes for team %q)", existingBytes, len(req.Content)+len(req.FileName), h.openClawQuota.MaxIdentityTotalBytes, team))
		return
	}

	rateKey := openClawRateKey(team, user.ID)
	if allowed, retryAfter := h.openClawRateLimiter.Allow(rateKey); !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(retryAfter)))
		writeError(w, http.StatusTooManyRequests, fmt.Sprintf("save rate limit exceeded for team %q (cap: %d writes/hour per user across skill + identity)", team, h.openClawQuota.SaveRatePerHour))
		return
	}

	op, ok := h.opts.Registry.Get("openclaw-identity-save")
	if !ok {
		writeError(w, http.StatusInternalServerError, "openclaw-identity-save operation is not registered")
		return
	}
	params := map[string]string{
		"team_name":   team,
		"file_name":   req.FileName,
		"content_b64": base64.StdEncoding.EncodeToString([]byte(req.Content)),
		"actor":       user.ID,
	}
	params = h.opts.Registry.ApplyDefaults(op, params)
	if errs := h.opts.Registry.ValidateInput(op, params); len(errs) > 0 {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":            "validation failed",
			"validationErrors": errs,
		})
		return
	}
	result, err := h.opts.Executor.Submit(r.Context(), op, params, user.ID, team)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to submit workflow: "+err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"workflow": result,
		"team":     team,
		"name":     req.FileName,
		"message":  "Identity save submitted. Wait for the workflow to succeed before the commit lands in gitops.",
	})
}

// DeleteOpenClawIdentity submits the openclaw-identity-delete workflow which
// removes the identity override file from the gitops backup. Idempotent.
// DELETE /api/v1/openclaw/{team}/identity/{name}
func (h *Handlers) DeleteOpenClawIdentity(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	team := strings.TrimSpace(chi.URLParam(r, "team"))
	if _, denied := h.requireOpenClawOwner(w, r, user, team); denied {
		return
	}

	name := strings.TrimSpace(chi.URLParam(r, "name"))
	if err := validateOpenClawIdentityFileName(name); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	rateKey := openClawRateKey(team, user.ID)
	if allowed, retryAfter := h.openClawRateLimiter.Allow(rateKey); !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(retryAfter)))
		writeError(w, http.StatusTooManyRequests, fmt.Sprintf("write rate limit exceeded for team %q (cap: %d writes/hour per user across skill + identity)", team, h.openClawQuota.SaveRatePerHour))
		return
	}

	op, ok := h.opts.Registry.Get("openclaw-identity-delete")
	if !ok {
		writeError(w, http.StatusInternalServerError, "openclaw-identity-delete operation is not registered")
		return
	}
	params := map[string]string{
		"team_name": team,
		"file_name": name,
		"actor":     user.ID,
	}
	params = h.opts.Registry.ApplyDefaults(op, params)
	if errs := h.opts.Registry.ValidateInput(op, params); len(errs) > 0 {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":            "validation failed",
			"validationErrors": errs,
		})
		return
	}
	result, err := h.opts.Executor.Submit(r.Context(), op, params, user.ID, team)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to submit workflow: "+err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"workflow": result,
		"team":     team,
		"name":     name,
		"message":  "Identity delete submitted.",
	})
}
