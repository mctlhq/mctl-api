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
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// testWorkflowID stands in for temporalclient.WorkflowIDForIssueURL: only
// mctlhq issues are startable.
func testWorkflowID(url string) (string, error) {
	const prefix = "https://github.com/mctlhq/"
	rest, ok := strings.CutPrefix(url, prefix)
	if !ok {
		return "", fmt.Errorf("not an mctlhq issue: %s", url)
	}
	repo, num, _ := strings.Cut(rest, "/issues/")
	return "dev-loop-mctlhq-" + repo + "-" + num, nil
}

// publishedItems is the enterprise-mcp ready set as published, by id.
func publishedItems(t *testing.T, epic string) map[string]waveItemWire {
	t.Helper()
	pub := livePublication(t)
	e, err := pub.find(epic)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]waveItemWire{}
	for _, it := range e.items {
		var w waveItemWire
		if err := json.Unmarshal(it.raw, &w); err != nil {
			t.Fatal(err)
		}
		out[it.id] = w
	}
	return out
}

func TestWavePlanSelectsExactlyTheReadyBoundItems(t *testing.T) {
	pub := livePublication(t)
	items := publishedItems(t, "enterprise-mcp")
	for _, requiredOnly := range []bool{true, false} {
		plan, err := pub.PlanWave(WaveRequest{Epic: "mctlhq/.github#35", RequiredOnly: requiredOnly}, testWorkflowID, liveNow)
		if err != nil {
			t.Fatal(err)
		}
		var want []string
		for id, w := range items {
			if w.State == StateReady && (w.Required || !requiredOnly) {
				want = append(want, id)
			}
		}
		if got := plan.SelectedIDs(); !equalSorted(got, want) || len(got) < 2 {
			t.Fatalf("required_only=%v: selected %v, want %v", requiredOnly, got, want)
		}
		for _, it := range plan.Selected {
			w := items[it.ID]
			if w.State != StateReady || it.Issue != *w.Issue || it.IssueURL != IssueURL(*w.Issue) ||
				it.WorkflowID != fmt.Sprintf("dev-loop-mctlhq-%s-%d", strings.TrimPrefix(w.Issue.Repository, "mctlhq/"), w.Issue.Number) {
				t.Errorf("selected %+v, published %+v", it, w)
			}
		}
	}
}

func TestWavePlanNeverStartsWhatIsNotEligible(t *testing.T) {
	pub := livePublication(t)
	items := publishedItems(t, "enterprise-mcp")
	var blocked, optional, ready string
	for id, w := range items {
		switch {
		case w.State != StateReady && blocked == "":
			blocked = id
		case w.State == StateReady && !w.Required && optional == "":
			optional = id
		case w.State == StateReady && w.Required && ready == "":
			ready = id
		}
	}
	if blocked == "" || optional == "" || ready == "" {
		t.Fatalf("the fixture no longer has a blocked, an optional and a required ready item: %v", items)
	}
	for _, c := range []struct {
		items  []string
		reason string
	}{
		{[]string{ready, blocked}, RefusalNotReady},
		{[]string{ready, "no-such-item"}, RefusalUnknownItem},
		{[]string{ready, optional}, RefusalOptional},
		{[]string{ready, ready}, RefusalDuplicateItem},
	} {
		_, err := pub.PlanWave(WaveRequest{Epic: "enterprise-mcp", RequiredOnly: true, Items: c.items}, testWorkflowID, liveNow)
		var sel *SelectionError
		if !errors.As(err, &sel) || !errors.Is(err, ErrInvalidSelection) {
			t.Fatalf("%v: %v, want a selection error and no plan", c.items, err)
		}
		if len(sel.Refused) != 1 || sel.Refused[0].Reason != c.reason {
			t.Errorf("%v: refused %+v, want %s", c.items, sel.Refused, c.reason)
		}
	}
	// An optional item is plannable once asked for explicitly.
	if plan, err := pub.PlanWave(WaveRequest{Epic: "enterprise-mcp", RequiredOnly: false, Items: []string{optional}}, testWorkflowID, liveNow); err != nil || len(plan.Selected) != 1 {
		t.Fatalf("explicit optional item: %v", err)
	}
}

func TestWavePlanRefusesUnboundAndUnstartableItemsVisibly(t *testing.T) {
	files := liveFiles(t)
	var unbound, foreign string
	editJSON(t, files, ReadySetFile, func(doc map[string]any) {
		for _, raw := range doc["items"].([]any) {
			epic := raw.(map[string]any)
			if epic["epic"].(map[string]any)["name"] != "enterprise-mcp" {
				continue
			}
			for _, it := range epic["items"].([]any) {
				item := it.(map[string]any)
				if item["state"] != StateReady || item["required"] != true {
					continue
				}
				switch {
				case unbound == "":
					unbound = item["id"].(string)
					delete(item, "issue")
				case foreign == "":
					foreign = item["id"].(string)
					item["issue"].(map[string]any)["repository"] = "someone-else/repo"
				}
			}
		}
	})
	resign(t, files)
	pub, err := Parse(files, "0000000000000000000000000000000000000002")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := pub.PlanWave(WaveRequest{Epic: "enterprise-mcp", RequiredOnly: true}, testWorkflowID, liveNow)
	if err != nil {
		t.Fatal(err)
	}
	reasons := map[string]string{}
	for _, r := range plan.Refused {
		reasons[r.ID] = r.Reason
	}
	if reasons[unbound] != RefusalUnbound || reasons[foreign] != RefusalNotStartable {
		t.Fatalf("refused = %+v", plan.Refused)
	}
	for _, id := range plan.SelectedIDs() {
		if id == unbound || id == foreign {
			t.Fatalf("%s was selected", id)
		}
	}
	for _, id := range []string{unbound, foreign} {
		if _, err := pub.PlanWave(WaveRequest{Epic: "enterprise-mcp", RequiredOnly: true, Items: []string{id}}, testWorkflowID, liveNow); !errors.Is(err, ErrInvalidSelection) {
			t.Errorf("explicit %s: %v", id, err)
		}
	}
}

func TestWavePlanHashBindsPublicationAndSelection(t *testing.T) {
	pub := livePublication(t)
	all, err := pub.PlanWave(WaveRequest{Epic: "enterprise-mcp", RequiredOnly: true}, testWorkflowID, liveNow)
	if err != nil {
		t.Fatal(err)
	}
	ids := all.SelectedIDs()
	reversed := []string{ids[len(ids)-1]}
	reversed = append(reversed, ids[:len(ids)-1]...)
	explicit, err := pub.PlanWave(WaveRequest{Epic: "enterprise-mcp", RequiredOnly: true, Items: reversed}, testWorkflowID, liveNow)
	if err != nil {
		t.Fatal(err)
	}
	// The same set is the same plan, however it was asked for, and whenever.
	later, _ := pub.PlanWave(WaveRequest{Epic: "enterprise-mcp", RequiredOnly: true}, testWorkflowID, liveNow.Add(3600e9))
	if explicit.PlanHash != all.PlanHash || later.PlanHash != all.PlanHash || !strings.HasPrefix(all.OperationID, "wave-") {
		t.Fatalf("hashes %s / %s / %s", all.PlanHash, explicit.PlanHash, later.PlanHash)
	}
	subset, _ := pub.PlanWave(WaveRequest{Epic: "enterprise-mcp", RequiredOnly: true, Items: ids[:1]}, testWorkflowID, liveNow)
	optional, _ := pub.PlanWave(WaveRequest{Epic: "enterprise-mcp", RequiredOnly: false, Items: ids}, testWorkflowID, liveNow)
	other, err := Parse(liveFiles(t), "0000000000000000000000000000000000000009")
	if err != nil {
		t.Fatal(err)
	}
	moved, _ := other.PlanWave(WaveRequest{Epic: "enterprise-mcp", RequiredOnly: true}, testWorkflowID, liveNow)
	for name, p := range map[string]*WavePlan{"subset": subset, "required_only": optional, "state_revision": moved} {
		if p.PlanHash == all.PlanHash {
			t.Errorf("a different %s kept the plan hash", name)
		}
	}
}

func TestWavePlanForAnEpicWithNothingReadyIsEmptyNotAnError(t *testing.T) {
	pub := livePublication(t)
	plan, err := pub.PlanWave(WaveRequest{Epic: "lifecycle-ownership", RequiredOnly: true}, testWorkflowID, liveNow)
	if err != nil || len(plan.Selected) != 0 {
		t.Fatalf("plan = %+v, %v", plan, err)
	}
	if _, err := pub.PlanWave(WaveRequest{Epic: "no-such-epic"}, testWorkflowID, liveNow); !errors.Is(err, ErrEpicNotFound) {
		t.Fatalf("unknown epic: %v", err)
	}
}
