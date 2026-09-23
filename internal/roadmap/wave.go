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

package roadmap

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Governed wave start (mctl-api#334). A wave plan is the exact set of
// already-ready, bound work items one epic's published ready set offers,
// bound to the publication it was read from. Selecting is all it does: the
// evaluator decided readiness, and the plan only refuses what it cannot
// start.

// WavePlanVersion names the plan-hash input format, so a change to what a
// plan binds can never collide with an older plan's hash.
const WavePlanVersion = "roadmap.mctl.ai/wave-plan/v1"

// Refusal reasons for a work item that cannot be part of a wave.
const (
	RefusalUnknownItem   = "unknown_item"           // no item by that id in the epic
	RefusalNotReady      = "not_ready"              // the published state is not ready
	RefusalOptional      = "optional_not_requested" // optional item without required_only=false
	RefusalUnbound       = "unbound"                // no exact repository + issue number
	RefusalNotStartable  = "not_startable"          // the issue cannot be turned into a DevLoop start
	RefusalDuplicateItem = "duplicate_item"         // the same id requested twice
)

// ErrEpicNotActive: the governed wave start runs only for an active epic.
// There is no implicit override (mctl-api#363): an operator override would
// be a separate, explicitly privileged operation.
var ErrEpicNotActive = errors.New("epic is not active")

// Reasons an epic is not active, by lifecycle.
const (
	EpicRefusalPaused    = "epic_paused"
	EpicRefusalCompleted = "epic_completed"
	EpicRefusalInactive  = "epic_not_active" // any other lifecycle
)

// EpicNotActiveError names the lifecycle that refused the wave.
type EpicNotActiveError struct {
	Epic      string
	Lifecycle string
}

func (e *EpicNotActiveError) Error() string {
	return fmt.Sprintf("%s: epic %s is %q", ErrEpicNotActive, e.Epic, e.Lifecycle)
}

func (e *EpicNotActiveError) Unwrap() error { return ErrEpicNotActive }

// Reason is the typed refusal for this lifecycle.
func (e *EpicNotActiveError) Reason() string {
	switch e.Lifecycle {
	case LifecyclePaused:
		return EpicRefusalPaused
	case LifecycleCompleted:
		return EpicRefusalCompleted
	}
	return EpicRefusalInactive
}

// ErrInvalidSelection: the requested selection cannot be planned exactly.
// A wave never starts a subset of what was asked for.
var ErrInvalidSelection = errors.New("invalid wave selection")

// SelectionError carries every refused item of an explicit selection.
type SelectionError struct {
	Refused []WaveRefusal
}

func (e *SelectionError) Error() string {
	parts := make([]string, 0, len(e.Refused))
	for _, r := range e.Refused {
		parts = append(parts, r.ID+": "+r.Reason)
	}
	if len(parts) == 0 {
		return ErrInvalidSelection.Error() + ": nothing selected"
	}
	return ErrInvalidSelection.Error() + ": " + strings.Join(parts, "; ")
}

func (e *SelectionError) Unwrap() error { return ErrInvalidSelection }

// WaveRequest is what a caller asks to plan. Items empty means every
// eligible item of the epic; otherwise exactly those ids, all or nothing.
type WaveRequest struct {
	Epic         string
	RequiredOnly bool
	Items        []string
}

// WaveItem is one work item a wave would start.
type WaveItem struct {
	ID         string   `json:"id"`
	Required   bool     `json:"required"`
	Issue      IssueRef `json:"issue"`
	IssueURL   string   `json:"issue_url"`
	WorkflowID string   `json:"workflow_id"`
}

// WaveRefusal is one work item a wave will not start, and why.
type WaveRefusal struct {
	ID     string    `json:"id"`
	Issue  *IssueRef `json:"issue,omitempty"`
	Reason string    `json:"reason"`
	State  string    `json:"state,omitempty"`
}

// WavePlan is an exact, publication-bound wave. PlanHash covers everything
// an execution must find unchanged; Refused is informational and is not
// part of it.
type WavePlan struct {
	PlanHash     string        `json:"plan_hash"`
	OperationID  string        `json:"operation_id"`
	Epic         Epic          `json:"epic"`
	RequiredOnly bool          `json:"required_only"`
	Selected     []WaveItem    `json:"selected"`
	Refused      []WaveRefusal `json:"refused"`
	Provenance   Provenance    `json:"provenance"`
}

// WorkflowIDFunc derives the exact DevLoop workflow id for an issue URL, or
// fails when the issue cannot be started through DevLoop.
type WorkflowIDFunc func(issueURL string) (string, error)

// IssueURL is the GitHub URL of an issue reference.
func IssueURL(ref IssueRef) string {
	return "https://github.com/" + ref.Repository + "/issues/" + strconv.Itoa(ref.Number)
}

type waveItemWire struct {
	ID       string    `json:"id"`
	Required bool      `json:"required"`
	State    string    `json:"state"`
	Issue    *IssueRef `json:"issue"`
}

// PlanWave selects a wave from this publication. Eligible means: the
// published state is ready, the item is required (or required_only is
// false), and it is bound to an exact issue that DevLoop can start.
//
// With no explicit items, ready items that are unbound or not startable are
// listed as refused, never dropped silently. With explicit items, any item
// that is not eligible fails the whole plan with a *SelectionError.
func (p *Publication) PlanWave(req WaveRequest, workflowID WorkflowIDFunc, now time.Time) (*WavePlan, error) {
	e, err := p.find(req.Epic)
	if err != nil {
		return nil, err
	}
	// Fail closed on anything but an active epic, before any item is
	// considered: a paused or completed epic's ready items are not work
	// the standard wave start may begin.
	if e.epic.Lifecycle != LifecycleActive {
		return nil, &EpicNotActiveError{Epic: e.epic.Name, Lifecycle: e.epic.Lifecycle}
	}
	byID := make(map[string]waveItemWire, len(e.items))
	order := make([]string, 0, len(e.items))
	for _, it := range e.items {
		var w waveItemWire
		if err := json.Unmarshal(it.raw, &w); err != nil {
			return nil, unavailable("%s: item %s: %v", e.epic.Manifest.Path, it.id, err)
		}
		byID[it.id] = w
		order = append(order, it.id)
	}

	plan := &WavePlan{
		Epic:         e.epic,
		RequiredOnly: req.RequiredOnly,
		Selected:     []WaveItem{},
		Refused:      []WaveRefusal{},
		Provenance:   p.Provenance(now),
	}
	// eligible reports why an item is not startable, or builds its WaveItem.
	eligible := func(id string) (*WaveItem, *WaveRefusal) {
		w, ok := byID[id]
		switch {
		case !ok:
			return nil, &WaveRefusal{ID: id, Reason: RefusalUnknownItem}
		case w.State != StateReady:
			return nil, &WaveRefusal{ID: id, Issue: w.Issue, Reason: RefusalNotReady, State: w.State}
		case !w.Required && req.RequiredOnly:
			return nil, &WaveRefusal{ID: id, Issue: w.Issue, Reason: RefusalOptional}
		case w.Issue == nil || w.Issue.Repository == "" || w.Issue.Number <= 0:
			return nil, &WaveRefusal{ID: id, Reason: RefusalUnbound}
		}
		url := IssueURL(*w.Issue)
		wf, err := workflowID(url)
		if err != nil {
			return nil, &WaveRefusal{ID: id, Issue: w.Issue, Reason: RefusalNotStartable}
		}
		return &WaveItem{ID: id, Required: w.Required, Issue: *w.Issue, IssueURL: url, WorkflowID: wf}, nil
	}

	if len(req.Items) == 0 {
		for _, id := range order {
			w := byID[id]
			if w.State != StateReady || (!w.Required && req.RequiredOnly) {
				continue // not a candidate at all
			}
			if item, refusal := eligible(id); refusal != nil {
				plan.Refused = append(plan.Refused, *refusal)
			} else {
				plan.Selected = append(plan.Selected, *item)
			}
		}
	} else {
		requested := map[string]bool{}
		var refused []WaveRefusal
		for _, id := range req.Items {
			if requested[id] {
				refused = append(refused, WaveRefusal{ID: id, Reason: RefusalDuplicateItem})
				continue
			}
			requested[id] = true
			if _, refusal := eligible(id); refusal != nil {
				refused = append(refused, *refusal)
			}
		}
		if len(refused) > 0 {
			return nil, &SelectionError{Refused: refused}
		}
		// Published order, not request order: the same set is the same plan.
		for _, id := range order {
			if requested[id] {
				item, _ := eligible(id)
				plan.Selected = append(plan.Selected, *item)
			}
		}
	}
	plan.PlanHash = plan.hash()
	plan.OperationID = "wave-" + plan.PlanHash[:16]
	return plan, nil
}

// hash binds the plan to its publication, manifest and exact selection.
func (plan *WavePlan) hash() string {
	type sel struct {
		ID         string `json:"id"`
		Repository string `json:"repository"`
		Number     int    `json:"number"`
		WorkflowID string `json:"workflow_id"`
	}
	in := struct {
		Version           string `json:"version"`
		Epic              string `json:"epic"`
		ManifestPath      string `json:"manifest_path"`
		ManifestSHA256    string `json:"manifest_sha256"`
		ManifestRevision  string `json:"manifest_revision"`
		StateRevision     string `json:"state_revision"`
		EvaluatorRevision string `json:"evaluator_revision"`
		RequiredOnly      bool   `json:"required_only"`
		Selected          []sel  `json:"selected"`
	}{
		Version:           WavePlanVersion,
		Epic:              plan.Epic.Name,
		ManifestPath:      plan.Epic.Manifest.Path,
		ManifestSHA256:    plan.Epic.Manifest.SHA256,
		ManifestRevision:  plan.Provenance.Source.Revision,
		StateRevision:     plan.Provenance.StateRevision,
		EvaluatorRevision: plan.Provenance.EvaluatorRevision,
		RequiredOnly:      plan.RequiredOnly,
		Selected:          []sel{},
	}
	for _, it := range plan.Selected {
		in.Selected = append(in.Selected, sel{it.ID, it.Issue.Repository, it.Issue.Number, it.WorkflowID})
	}
	data, err := json.Marshal(in)
	if err != nil {
		// Only strings, ints and bools: unreachable.
		panic(fmt.Sprintf("roadmap: wave plan hash: %v", err))
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// SelectedIDs are the ids of the selected items, in plan order.
func (plan *WavePlan) SelectedIDs() []string {
	ids := make([]string, 0, len(plan.Selected))
	for _, it := range plan.Selected {
		ids = append(ids, it.ID)
	}
	return ids
}
