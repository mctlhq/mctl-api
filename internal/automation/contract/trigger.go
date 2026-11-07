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

package contract

import (
	"regexp"
	"slices"
	"time"
	// Embedded so DST behaviour does not depend on host tzdata.
	_ "time/tzdata"
)

// mvpTriggers is the MVP gate on (template, kind) pairs: only reminder.v1
// with "at" is enabled. Support templates are not enabled yet.
var mvpTriggers = map[string][]string{"reminder.v1": {"at"}}

var offsetOnlyZone = regexp.MustCompile(`^(UTC|GMT)?[+-]?[0-9]`)

// CheckTrigger applies the semantic rules the schema cannot express: the MVP
// gate, the template's allowed kinds, unsupported event sources and the local
// time resolution (zone, DST gap and fold).
func CheckTrigger(trig map[string]any, tmpl Template) error {
	k, _ := trig["kind"].(string)
	if !slices.Contains(mvpTriggers[tmpl.ID], k) || !slices.Contains(tmpl.AllowedTriggers, k) {
		return fail(CodeTriggerUnsupported, "trigger kind %q", k)
	}
	if k == "event" {
		return fail(CodeTriggerUnsupported, "event triggers")
	}
	if instant, ok := trig["instant"].(string); ok {
		if _, err := time.Parse(time.RFC3339, instant); err != nil {
			return fail(CodeInvalid, "instant is not RFC 3339")
		}
		return nil
	}
	local, _ := trig["local"].(string)
	zone, _ := trig["zone"].(string)
	gap, _ := trig["dst_gap"].(string)
	fold, _ := trig["dst_fold"].(string)
	_, err := ResolveAt(local, zone, gap, fold)
	return err
}

// ResolveAt resolves a wall-clock local time in an IANA zone to an instant.
//
// A nonexistent (spring-forward) time follows gap: "shift_forward" or
// "reject". An ambiguous (fall-back) time follows fold: "earlier", "later" or
// "reject". "reject" yields automation_time_ambiguous. An unknown zone or an
// offset-only zone yields automation_invalid. See docs/automation-contract.md.
func ResolveAt(local, zone, gap, fold string) (time.Time, error) {
	if zone == "" || zone == "Local" || offsetOnlyZone.MatchString(zone) {
		return time.Time{}, fail(CodeInvalid, "zone must be an IANA zone name")
	}
	loc, err := time.LoadLocation(zone)
	if err != nil {
		return time.Time{}, fail(CodeInvalid, "unknown zone %q", zone)
	}
	wall, err := time.Parse("2006-01-02T15:04:05", local)
	if err != nil {
		return time.Time{}, fail(CodeInvalid, "local time is malformed")
	}
	if gap != "shift_forward" && gap != "reject" {
		return time.Time{}, fail(CodeInvalid, "dst_gap must be shift_forward or reject")
	}
	if fold != "earlier" && fold != "later" && fold != "reject" {
		return time.Time{}, fail(CodeInvalid, "dst_fold must be earlier, later or reject")
	}
	// wall is the local reading taken as UTC. Offsets just before and after
	// the wall time bracket any transition around it.
	_, offBefore := wall.Add(-24 * time.Hour).In(loc).Zone()
	_, offAfter := wall.Add(24 * time.Hour).In(loc).Zone()
	var cands []time.Time
	for _, off := range []int{offBefore, offAfter} {
		u := wall.Add(-time.Duration(off) * time.Second)
		w := u.In(loc)
		if w.Format("2006-01-02T15:04:05") == local && !slices.ContainsFunc(cands, u.Equal) {
			cands = append(cands, u)
		}
	}
	switch len(cands) {
	case 1:
		return cands[0], nil
	case 0: // gap
		if gap == "reject" {
			return time.Time{}, fail(CodeTimeAmbiguous, "local time does not exist in %s", zone)
		}
		// Interpreting the wall time with the pre-transition offset lands
		// after the gap.
		return wall.Add(-time.Duration(offBefore) * time.Second), nil
	default: // fold
		if fold == "reject" {
			return time.Time{}, fail(CodeTimeAmbiguous, "local time is ambiguous in %s", zone)
		}
		slices.SortFunc(cands, func(a, b time.Time) int { return a.Compare(b) })
		if fold == "earlier" {
			return cands[0], nil
		}
		return cands[1], nil
	}
}
