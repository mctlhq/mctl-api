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
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// testdata/live is a real publication, copied byte for byte from the
// roadmap-state branch of mctlhq/.github (see testdata/live/SOURCE). The
// tests compare what this package serves against those bytes; they never
// restate an expected readiness of their own.
const liveDir = "testdata/live"

var liveNow = time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)

func liveFiles(t *testing.T) map[string][]byte {
	t.Helper()
	files := map[string][]byte{}
	for _, name := range []string{PublicationFile, SnapshotFile, ReadySetFile, HealthFile} {
		data, err := os.ReadFile(filepath.Join(liveDir, name)) //nolint:gosec // fixed fixture names
		if err != nil {
			t.Fatal(err)
		}
		files[name] = data
	}
	return files
}

func livePublication(t *testing.T) *Publication {
	t.Helper()
	pub, err := Parse(liveFiles(t), "0000000000000000000000000000000000000001")
	if err != nil {
		t.Fatalf("the live publication does not verify: %v", err)
	}
	return pub
}

type publishedDoc struct {
	Epic struct {
		Name string `json:"name"`
	} `json:"epic"`
	Items []struct {
		ID       string    `json:"id"`
		Required bool      `json:"required"`
		State    string    `json:"state"`
		Issue    *IssueRef `json:"issue"`
	} `json:"items"`
	Ready []string `json:"ready"`
}

func publishedList(t *testing.T, file string) map[string]json.RawMessage {
	t.Helper()
	var list struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(liveFiles(t)[file], &list); err != nil {
		t.Fatal(err)
	}
	out := map[string]json.RawMessage{}
	for _, raw := range list.Items {
		var doc publishedDoc
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		out[doc.Epic.Name] = raw
	}
	return out
}

func TestEpicStatusIsThePublishedDocumentsByteForByte(t *testing.T) {
	pub := livePublication(t)
	ready := publishedList(t, ReadySetFile)
	health := publishedList(t, HealthFile)
	if len(pub.Epics()) != len(ready) || len(ready) == 0 {
		t.Fatalf("serves %d epics, the ready set has %d", len(pub.Epics()), len(ready))
	}
	for _, e := range pub.Epics() {
		status, err := pub.EpicStatus(e.Name, liveNow)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(status.Readiness, ready[e.Name]) || !bytes.Equal(status.Health, health[e.Name]) {
			t.Errorf("%s: served documents differ from the published ones", e.Name)
		}
	}
}

func TestReadyItemsAreExactlyThePublishedReadyList(t *testing.T) {
	pub := livePublication(t)
	for name, raw := range publishedList(t, ReadySetFile) {
		var doc publishedDoc
		_ = json.Unmarshal(raw, &doc)
		required := map[string]bool{}
		for _, it := range doc.Items {
			required[it.ID] = it.Required
		}
		for _, requiredOnly := range []bool{false, true} {
			got, err := pub.ReadyWorkItems(name, requiredOnly, liveNow)
			if err != nil {
				t.Fatal(err)
			}
			var want []string
			for _, id := range doc.Ready {
				if required[id] || !requiredOnly {
					want = append(want, id)
				}
			}
			if ids := itemIDs(t, got.Epics[0].Items); !equalSorted(ids, want) {
				t.Errorf("%s required_only=%v: served %v, published %v", name, requiredOnly, ids, want)
			}
		}
	}
}

func TestAllEpicsMeansEveryActiveEpicAndNoOther(t *testing.T) {
	pub := livePublication(t)
	var publication struct {
		Manifests []struct {
			Epic struct {
				Name      string `json:"name"`
				Lifecycle string `json:"lifecycle"`
			} `json:"epic"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal(liveFiles(t)[PublicationFile], &publication); err != nil {
		t.Fatal(err)
	}
	var active, inactive []string
	for _, m := range publication.Manifests {
		if m.Epic.Lifecycle == "active" {
			active = append(active, m.Epic.Name)
		} else {
			inactive = append(inactive, m.Epic.Name)
		}
	}
	if len(active) == 0 || len(inactive) == 0 {
		t.Fatalf("fixture must hold active and inactive epics: %v / %v", active, inactive)
	}
	got, err := pub.ReadyWorkItems("", true, liveNow)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range got.Epics {
		names = append(names, e.Epic.Name)
	}
	if !equalSorted(names, active) {
		t.Fatalf("all-epics answer covers %v, the active epics are %v", names, active)
	}
}

// The #333 acceptance examples, read against the live publication: whatever
// the evaluator decided is what is served, and no unbound or unobserved item
// is ever offered as executable.
func TestAcceptanceExamplesFollowThePublication(t *testing.T) {
	pub := livePublication(t)

	// Enterprise MCP (#35): several independent required items can be ready.
	mcp, err := pub.ReadyWorkItems("mctlhq/.github#35", true, liveNow)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(mcp.Epics[0].Items); n < 2 {
		t.Errorf("enterprise MCP serves %d ready items; the publication lists at least two", n)
	}

	// Nothing unbound or unknown is ever served as ready, in any epic.
	all, err := pub.ReadyWorkItems("", false, liveNow)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range all.Epics {
		for _, raw := range e.Items {
			var it struct {
				State string    `json:"state"`
				Issue *IssueRef `json:"issue"`
			}
			_ = json.Unmarshal(raw, &it)
			if it.State != StateReady || it.Issue == nil {
				t.Errorf("%s served a non-ready or unbound item: %s", e.Epic.Name, raw)
			}
		}
	}

	// Lookup by root issue is the same epic as lookup by name.
	byIssue, err := pub.EpicStatus("MCTLHQ/.github#57", liveNow)
	if err != nil {
		t.Fatal(err)
	}
	byName, err := pub.EpicStatus(byIssue.Epic.Name, liveNow)
	if err != nil || !bytes.Equal(byName.Readiness, byIssue.Readiness) {
		t.Fatalf("root issue and name disagree: %v", err)
	}
	if folded, err := pub.EpicStatus(strings.ToUpper(byIssue.Epic.Name), liveNow); err != nil || folded.Epic.Name != byIssue.Epic.Name {
		t.Fatalf("name lookup is not case-insensitive like the issue lookup: %v", err)
	}
	if _, err := pub.EpicStatus("no-such-epic", liveNow); !errors.Is(err, ErrEpicNotFound) {
		t.Fatalf("unknown epic: %v", err)
	}
}

func TestProvenanceCarriesTheCaptureAndItsAge(t *testing.T) {
	pub := livePublication(t)
	got, _ := pub.ReadyWorkItems("", true, liveNow)
	p := got.Provenance
	if p.Observation.Mode != "live-capture" || p.Observation.CapturedAt == nil || p.AgeSeconds == nil {
		t.Fatalf("provenance = %+v", p)
	}
	if want := int64(liveNow.Sub(*p.Observation.CapturedAt) / time.Second); *p.AgeSeconds != want {
		t.Fatalf("age = %d, want %d", *p.AgeSeconds, want)
	}
	if p.EvaluatorRevision == "" || p.Source.Revision == "" || p.StateRevision == "" {
		t.Fatalf("revisions missing: %+v", p)
	}
}

// resign recomputes the digests in publication.json after a test edits a
// file, so a tamper test reaches the check it is aimed at instead of
// stopping at the digest.
func resign(t *testing.T, files map[string][]byte) {
	t.Helper()
	var pub map[string]any
	if err := json.Unmarshal(files[PublicationFile], &pub); err != nil {
		t.Fatal(err)
	}
	digests := pub["files"].(map[string]any)
	for _, name := range []string{SnapshotFile, ReadySetFile, HealthFile} {
		sum := sha256.Sum256(files[name])
		digests[name] = map[string]any{"sha256": hex.EncodeToString(sum[:])}
	}
	files[PublicationFile] = mustJSON(t, pub)
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func editJSON(t *testing.T, files map[string][]byte, name string, edit func(doc map[string]any)) {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(files[name], &doc); err != nil {
		t.Fatal(err)
	}
	edit(doc)
	files[name] = mustJSON(t, doc)
}

func firstReadySet(doc map[string]any) map[string]any {
	return doc["items"].([]any)[0].(map[string]any)
}

func TestAnythingUnverifiedIsRefused(t *testing.T) {
	cases := map[string]func(t *testing.T, files map[string][]byte){
		"a file altered after publishing": func(t *testing.T, files map[string][]byte) {
			files[ReadySetFile] = append(bytes.Clone(files[ReadySetFile]), ' ')
		},
		"the snapshot altered after publishing": func(t *testing.T, files map[string][]byte) {
			files[SnapshotFile] = append(bytes.Clone(files[SnapshotFile]), ' ')
		},
		"a missing file": func(t *testing.T, files map[string][]byte) {
			delete(files, HealthFile)
		},
		"an unsupported apiVersion": func(t *testing.T, files map[string][]byte) {
			editJSON(t, files, PublicationFile, func(doc map[string]any) { doc["apiVersion"] = "roadmap.mctl.ai/v2" })
		},
		"a manifest without epic identity": func(t *testing.T, files map[string][]byte) {
			editJSON(t, files, PublicationFile, func(doc map[string]any) {
				delete(doc["manifests"].([]any)[0].(map[string]any), "epic")
			})
		},
		"a manifest whose epic has no lifecycle": func(t *testing.T, files map[string][]byte) {
			editJSON(t, files, PublicationFile, func(doc map[string]any) {
				delete(doc["manifests"].([]any)[0].(map[string]any)["epic"].(map[string]any), "lifecycle")
			})
		},
		"a manifest without a digest": func(t *testing.T, files map[string][]byte) {
			editJSON(t, files, PublicationFile, func(doc map[string]any) {
				for _, m := range doc["manifests"].([]any) {
					m.(map[string]any)["sha256"] = ""
				}
			})
			editJSON(t, files, ReadySetFile, func(doc map[string]any) {
				for _, d := range doc["items"].([]any) {
					d.(map[string]any)["epic"].(map[string]any)["manifest"].(map[string]any)["sha256"] = ""
				}
			})
			editJSON(t, files, HealthFile, func(doc map[string]any) {
				for _, d := range doc["items"].([]any) {
					d.(map[string]any)["epic"].(map[string]any)["manifest"].(map[string]any)["sha256"] = ""
				}
			})
			resign(t, files)
		},
		"two epics equal but for case": func(t *testing.T, files map[string][]byte) {
			var second string
			editJSON(t, files, PublicationFile, func(doc map[string]any) {
				ms := doc["manifests"].([]any)
				first := ms[0].(map[string]any)["epic"].(map[string]any)["name"].(string)
				e := ms[1].(map[string]any)["epic"].(map[string]any)
				second = e["name"].(string)
				e["name"] = strings.ToUpper(first)
			})
			for _, f := range []string{ReadySetFile, HealthFile} {
				editJSON(t, files, f, func(doc map[string]any) {
					for _, d := range doc["items"].([]any) {
						e := d.(map[string]any)["epic"].(map[string]any)
						if e["name"] == second {
							var pub map[string]any
							_ = json.Unmarshal(files[PublicationFile], &pub)
							e["name"] = pub["manifests"].([]any)[1].(map[string]any)["epic"].(map[string]any)["name"]
						}
					}
				})
			}
			resign(t, files)
		},
		"a live capture without capturedAt": func(t *testing.T, files map[string][]byte) {
			editJSON(t, files, PublicationFile, func(doc map[string]any) {
				delete(doc["observation"].(map[string]any), "capturedAt")
			})
		},
		"a ready list that disagrees with item states": func(t *testing.T, files map[string][]byte) {
			editJSON(t, files, ReadySetFile, func(doc map[string]any) {
				rs := firstReadySet(doc)
				for _, raw := range rs["items"].([]any) {
					it := raw.(map[string]any)
					if it["state"] != StateReady {
						rs["ready"] = append(rs["ready"].([]any), it["id"])
						return
					}
				}
				t.Fatal("fixture epic has no non-ready item")
			})
			resign(t, files)
		},
		"an item in an unknown state": func(t *testing.T, files map[string][]byte) {
			editJSON(t, files, ReadySetFile, func(doc map[string]any) {
				// A non-ready item, so the ready list still agrees and only
				// the state vocabulary check can refuse it.
				for _, raw := range firstReadySet(doc)["items"].([]any) {
					if it := raw.(map[string]any); it["state"] != StateReady {
						it["state"] = "maybe"
						return
					}
				}
				t.Fatal("fixture epic has no non-ready item")
			})
			resign(t, files)
		},
		"a ready set derived from another manifest": func(t *testing.T, files map[string][]byte) {
			editJSON(t, files, ReadySetFile, func(doc map[string]any) {
				firstReadySet(doc)["epic"].(map[string]any)["manifest"].(map[string]any)["sha256"] = "00"
			})
			resign(t, files)
		},
		"an epic the publication does not name": func(t *testing.T, files map[string][]byte) {
			editJSON(t, files, PublicationFile, func(doc map[string]any) {
				doc["manifests"] = doc["manifests"].([]any)[1:]
			})
		},
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			files := liveFiles(t)
			tamper(t, files)
			if _, err := Parse(files, "rev"); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("err = %v, want ErrUnavailable", err)
			}
		})
	}
}

type fakeSource struct {
	rev   string
	files map[string][]byte
	reads int
}

func (f *fakeSource) Revision() (string, error) { return f.rev, nil }
func (f *fakeSource) ReadFiles(names ...string) (map[string][]byte, string, error) {
	f.reads++
	out := map[string][]byte{}
	for _, n := range names {
		if data, ok := f.files[n]; ok {
			out[n] = data
		}
	}
	return out, f.rev, nil
}

func TestReaderReverifiesOnlyWhenTheCheckoutMovesAndNeverServesStale(t *testing.T) {
	src := &fakeSource{rev: "a", files: liveFiles(t)}
	r := NewReader(src)
	if _, err := r.Current(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Current(); err != nil || src.reads != 1 {
		t.Fatalf("same revision re-read the files: reads=%d err=%v", src.reads, err)
	}
	// The checkout moves to a broken publication: the previous good one must
	// not be served in its place.
	src.rev = "b"
	src.files[ReadySetFile] = []byte("{}")
	if _, err := r.Current(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("broken publication: err = %v", err)
	}
	if _, err := r.Current(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("broken publication, asked again: err = %v", err)
	}
	if src.reads != 2 {
		t.Fatalf("a broken revision was re-verified on every call: reads=%d", src.reads)
	}
	// It moves again, to a good publication: served at once.
	src.rev = "c"
	src.files = liveFiles(t)
	if _, err := r.Current(); err != nil {
		t.Fatalf("repaired publication: %v", err)
	}
	var nilReader *Reader
	if _, err := nilReader.Current(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unconfigured reader: err = %v", err)
	}
}

func itemIDs(t *testing.T, items []json.RawMessage) []string {
	t.Helper()
	ids := []string{}
	for _, raw := range items {
		var it struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(raw, &it); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, it.ID)
	}
	return ids
}

func equalSorted(a, b []string) bool {
	a, b = append([]string{}, a...), append([]string{}, b...)
	sort.Strings(a)
	sort.Strings(b)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
