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

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/glovoc2control"
)

// glovoC2KillSwitchPath is relative to /api/v1.
const glovoC2KillSwitchPath = "/admin/glovo-c2/kill-switch"

// glovoC2KillSwitchOperation is the audit operation name of every flip attempt.
const glovoC2KillSwitchOperation = "glovo.c2.killswitch.set"

// GlovoC2KillSwitchSetter flips mctl-glovo's runtime kill switch.
type GlovoC2KillSwitchSetter interface {
	SetKilled(ctx context.Context, killed bool) (glovoc2control.State, error)
}

// GlovoC2KillSwitch configures the admin kill-switch route. A nil value leaves
// the route unmounted (404): the feature is dark unless the env turns it on.
type GlovoC2KillSwitch struct {
	Setter GlovoC2KillSwitchSetter
}

func (g *GlovoC2KillSwitch) mounted() bool { return g != nil }

type glovoC2KillRequest struct {
	Killed *bool `json:"killed"`
}

// SetGlovoC2KillSwitch (POST /api/v1/admin/glovo-c2/kill-switch). Same
// authorization as the other direct-admin routes: a direct human platform
// administrator only (no service, relay, surface, agent or delegated caller).
// Success is reported only when mctl-glovo confirmed the requested state;
// every upstream failure is a 502 with state "unknown", never "switched off".
func (h *Handlers) SetGlovoC2KillSwitch(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	u := auth.UserFromContext(r.Context())
	if !directHumanAdmin(u) {
		writeError(w, http.StatusForbidden, "direct human platform administrator required")
		return
	}
	k := h.opts.GlovoC2KillSwitch
	if k == nil || k.Setter == nil {
		writeError(w, http.StatusServiceUnavailable, "glovo c2 kill switch unavailable")
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1025))
	if err != nil || len(raw) > 1024 {
		writeError(w, http.StatusBadRequest, "invalid kill switch request")
		return
	}
	var req glovoC2KillRequest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || req.Killed == nil || dec.More() {
		writeError(w, http.StatusBadRequest, `body must be {"killed": true|false}`)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	st, err := k.Setter.SetKilled(ctx, *req.Killed)
	requested := strconv.FormatBool(*req.Killed)
	if err != nil || st.Killed != *req.Killed {
		// err is token-free by construction (glovoc2control keeps a coarse class).
		slog.Error("glovo c2 kill switch flip not confirmed", "requested", *req.Killed, "principal", u.PrincipalID(), "error", err)
		msg := "state unknown"
		if err != nil {
			msg = err.Error()
		}
		h.logAudit(r, audit.Entry{UserID: u.ID, Operation: glovoC2KillSwitchOperation, Status: "failed", RiskLevel: "high", Message: msg, Parameters: map[string]string{"requested": requested, "state": "unknown"}})
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"error": "kill switch state could not be confirmed",
			"state": "unknown",
		})
		return
	}
	h.logAudit(r, audit.Entry{UserID: u.ID, Operation: glovoC2KillSwitchOperation, Status: "succeeded", RiskLevel: "high", Parameters: map[string]string{"requested": requested, "state": "confirmed"}})
	slog.Warn("glovo c2 kill switch set", "killed", st.Killed, "principal", u.PrincipalID())
	writeJSON(w, http.StatusOK, map[string]any{"killed": st.Killed, "confirmed": true})
}
