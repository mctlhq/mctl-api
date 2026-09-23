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

// Package roadmap is a read-only view of the RoadmapPublication that
// mctlhq/.github publishes to its generated `roadmap-state` branch
// (mctlhq/.github#119).
//
// It never evaluates anything. Readiness, completion and health are the
// Roadmap Control Plane's answers, computed once from one observation; this
// package verifies that the published files are the ones the publication
// names, then selects from them. An item is ready here only because the
// published ready set says so. Anything it cannot verify, it refuses to serve.
package roadmap

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// APIVersion is the only publication version this reader understands.
const APIVersion = "roadmap.mctl.ai/v1alpha1"

// Published file names, flat at the root of the roadmap-state branch.
const (
	PublicationFile = "publication.json"
	SnapshotFile    = "snapshot.json"
	ReadySetFile    = "ready-set.json"
	HealthFile      = "health.json"
)

// Evaluator item states. The reader never assigns one; it only reads them.
const (
	StateComplete = "complete"
	StateReady    = "ready"
	StateBlocked  = "blocked"
	StateUnknown  = "unknown"
)

// LifecycleActive is the EpicDefinition lifecycle selected by "all epics".
const LifecycleActive = "active"

var (
	// ErrUnavailable: there is no publication this reader can trust. It means
	// "cannot say", never "nothing is ready".
	ErrUnavailable = errors.New("roadmap publication unavailable")
	// ErrEpicNotFound: the publication has no epic by that name or root issue.
	ErrEpicNotFound = errors.New("epic not found in the roadmap publication")
)

// FileSource reads the published files. ReadFiles returns every name from one
// consistent checkout, together with that checkout's commit.
type FileSource interface {
	Revision() (string, error)
	ReadFiles(names ...string) (map[string][]byte, string, error)
}

// IssueRef is a GitHub issue as the evaluator names it.
type IssueRef struct {
	Repository string `json:"repository"`
	Number     int    `json:"number"`
}

func (r IssueRef) String() string { return r.Repository + "#" + strconv.Itoa(r.Number) }

// ManifestRef is the EpicDefinition file an answer was derived from.
type ManifestRef struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Epic is an epic's identity and lifecycle as the publication records it.
type Epic struct {
	Name      string      `json:"name"`
	Lifecycle string      `json:"lifecycle"`
	Title     string      `json:"title"`
	Goal      string      `json:"goal"`
	Issue     *IssueRef   `json:"issue,omitempty"`
	Manifest  ManifestRef `json:"manifest"`
}

// Observation is the single GitHub observation everything was derived from.
type Observation struct {
	Mode       string     `json:"mode"`
	CapturedAt *time.Time `json:"capturedAt,omitempty"`
	APIBase    string     `json:"apiBase,omitempty"`
}

// Provenance says where an answer came from and how old it is. Every
// response carries it, so a caller can judge freshness itself.
type Provenance struct {
	StateRevision     string      `json:"state_revision"`
	EvaluatorRevision string      `json:"evaluator_revision"`
	Source            SourceRef   `json:"source"`
	Observation       Observation `json:"observation"`
	// AgeSeconds is now minus observation.capturedAt; absent when the
	// observation carries no capture time (a synthetic fixture is never fresh).
	AgeSeconds *int64 `json:"age_seconds,omitempty"`
}

// SourceRef is where the manifests were read.
type SourceRef struct {
	Repository string `json:"repository"`
	Ref        string `json:"ref"`
	Revision   string `json:"revision"`
}

// EpicStatus is the composition of the published views for one epic.
type EpicStatus struct {
	Epic Epic `json:"epic"`
	// Readiness and Health are the published RoadmapReadySet and RoadmapHealth
	// documents for this epic, byte for byte.
	Readiness  json.RawMessage `json:"readiness"`
	Health     json.RawMessage `json:"health"`
	Provenance Provenance      `json:"provenance"`
}

// ReadyEpic is one epic's executable candidates.
type ReadyEpic struct {
	Epic Epic `json:"epic"`
	// Source is the epic's own observation block from the ready set.
	Source json.RawMessage `json:"source"`
	// Items are the published ready-set items, verbatim, whose id the ready
	// set lists as ready.
	Items []json.RawMessage `json:"items"`
}

// ReadyWorkItems answers "what work is ready now".
type ReadyWorkItems struct {
	RequiredOnly bool        `json:"required_only"`
	Epics        []ReadyEpic `json:"epics"`
	Provenance   Provenance  `json:"provenance"`
}

// Publication is one verified, parsed publication.
type Publication struct {
	revision string
	prov     Provenance
	epics    []*epicEntry // manifest path order, as published
}

type epicEntry struct {
	epic      Epic
	readiness json.RawMessage
	health    json.RawMessage
	source    json.RawMessage
	items     []item
}

type item struct {
	id       string
	required bool
	state    string
	raw      json.RawMessage
}

// Wire shapes, only as much as verification and selection need.
type wirePublication struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Evaluator  struct {
		Revision string `json:"revision"`
	} `json:"evaluator"`
	Source    SourceRef `json:"source"`
	Manifests []struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
		Epic   *struct {
			Name      string `json:"name"`
			Lifecycle string `json:"lifecycle"`
			Title     string `json:"title"`
			Goal      string `json:"goal"`
		} `json:"epic"`
	} `json:"manifests"`
	Observation Observation `json:"observation"`
	Files       map[string]struct {
		SHA256 string `json:"sha256"`
	} `json:"files"`
}

type wireList struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Items      []json.RawMessage `json:"items"`
}

type wireEpicDoc struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Epic       struct {
		Name     string      `json:"name"`
		Issue    *IssueRef   `json:"issue"`
		Manifest ManifestRef `json:"manifest"`
	} `json:"epic"`
	Source json.RawMessage   `json:"source"`
	Items  []json.RawMessage `json:"items"`
	Ready  []string          `json:"ready"`
}

type wireItem struct {
	ID       string `json:"id"`
	Required *bool  `json:"required"`
	State    string `json:"state"`
}

func unavailable(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrUnavailable, fmt.Sprintf(format, args...))
}

// Parse verifies and parses one publication. files must hold all four
// published files; revision is the roadmap-state commit they came from.
func Parse(files map[string][]byte, revision string) (*Publication, error) {
	for _, name := range []string{PublicationFile, SnapshotFile, ReadySetFile, HealthFile} {
		if _, ok := files[name]; !ok {
			return nil, unavailable("%s is missing", name)
		}
	}
	var pub wirePublication
	if err := json.Unmarshal(files[PublicationFile], &pub); err != nil {
		return nil, unavailable("%s: %v", PublicationFile, err)
	}
	if pub.APIVersion != APIVersion || pub.Kind != "RoadmapPublication" {
		return nil, unavailable("unsupported publication %s/%s", pub.APIVersion, pub.Kind)
	}
	if pub.Evaluator.Revision == "" || pub.Source.Revision == "" {
		return nil, unavailable("publication carries no evaluator or source revision")
	}
	// The digests are the publication's claim about the other three files;
	// a file that does not match it is not part of this publication.
	for _, name := range []string{SnapshotFile, ReadySetFile, HealthFile} {
		want := pub.Files[name].SHA256
		sum := sha256.Sum256(files[name])
		if want == "" || hex.EncodeToString(sum[:]) != want {
			return nil, unavailable("%s does not match the digest in %s", name, PublicationFile)
		}
	}
	if pub.Observation.Mode == "live-capture" && pub.Observation.CapturedAt == nil {
		return nil, unavailable("a live capture without capturedAt")
	}
	if len(pub.Manifests) == 0 {
		return nil, unavailable("publication covers no manifests")
	}

	ready, err := parseList(files[ReadySetFile], "RoadmapReadySetList", "RoadmapReadySet")
	if err != nil {
		return nil, unavailable("%s: %v", ReadySetFile, err)
	}
	health, err := parseList(files[HealthFile], "RoadmapHealthList", "RoadmapHealth")
	if err != nil {
		return nil, unavailable("%s: %v", HealthFile, err)
	}

	out := &Publication{
		revision: revision,
		prov: Provenance{
			StateRevision:     revision,
			EvaluatorRevision: pub.Evaluator.Revision,
			Source:            pub.Source,
			Observation:       pub.Observation,
		},
	}
	names := map[string]bool{}
	for _, m := range pub.Manifests {
		if m.SHA256 == "" {
			return nil, unavailable("manifest %s carries no digest", m.Path)
		}
		if m.Epic == nil || m.Epic.Name == "" || m.Epic.Lifecycle == "" {
			return nil, unavailable("manifest %s carries no epic identity", m.Path)
		}
		// Folded, because lookup folds: two names equal but for case would
		// otherwise both verify and then resolve ambiguously.
		folded := strings.ToLower(m.Epic.Name)
		if names[folded] {
			return nil, unavailable("epic %s is published twice", m.Epic.Name)
		}
		names[folded] = true
		r, ok := ready[m.Path]
		if !ok {
			return nil, unavailable("%s has no ready set for %s", ReadySetFile, m.Path)
		}
		h, ok := health[m.Path]
		if !ok {
			return nil, unavailable("%s has no health for %s", HealthFile, m.Path)
		}
		delete(ready, m.Path)
		delete(health, m.Path)
		for _, doc := range []*parsedDoc{&r, &h} {
			if doc.wire.Epic.Manifest.SHA256 != m.SHA256 || doc.wire.Epic.Name != m.Epic.Name {
				return nil, unavailable("%s was derived from a different manifest than the publication names", m.Path)
			}
		}
		entry := &epicEntry{
			epic: Epic{
				Name: m.Epic.Name, Lifecycle: m.Epic.Lifecycle, Title: m.Epic.Title, Goal: m.Epic.Goal,
				Issue:    r.wire.Epic.Issue,
				Manifest: ManifestRef{Path: m.Path, SHA256: m.SHA256},
			},
			readiness: r.raw,
			health:    h.raw,
			source:    r.wire.Source,
		}
		if entry.items, err = parseItems(r.wire); err != nil {
			return nil, unavailable("%s: %v", m.Path, err)
		}
		out.epics = append(out.epics, entry)
	}
	if len(ready) != 0 || len(health) != 0 {
		return nil, unavailable("derived files cover epics the publication does not name")
	}
	return out, nil
}

type parsedDoc struct {
	raw  json.RawMessage
	wire wireEpicDoc
}

func parseList(data []byte, listKind, itemKind string) (map[string]parsedDoc, error) {
	var list wireList
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, err
	}
	if list.APIVersion != APIVersion || list.Kind != listKind {
		return nil, fmt.Errorf("unsupported %s/%s", list.APIVersion, list.Kind)
	}
	out := map[string]parsedDoc{}
	for _, raw := range list.Items {
		var doc wireEpicDoc
		if err := json.Unmarshal(raw, &doc); err != nil {
			return nil, err
		}
		if doc.APIVersion != APIVersion || doc.Kind != itemKind {
			return nil, fmt.Errorf("unsupported item %s/%s", doc.APIVersion, doc.Kind)
		}
		path := doc.Epic.Manifest.Path
		if _, dup := out[path]; dup || path == "" {
			return nil, fmt.Errorf("manifest %q is missing or repeated", path)
		}
		out[path] = parsedDoc{raw: raw, wire: doc}
	}
	return out, nil
}

// parseItems reads the ready set's items and checks that its `ready` list
// and the items' own states say the same thing. The two are one answer from
// one evaluator; if they disagree the document is not one we can serve.
func parseItems(doc wireEpicDoc) ([]item, error) {
	listed := map[string]bool{}
	for _, id := range doc.Ready {
		listed[id] = true
	}
	items := make([]item, 0, len(doc.Items))
	seen := map[string]bool{}
	for _, raw := range doc.Items {
		var w wireItem
		if err := json.Unmarshal(raw, &w); err != nil {
			return nil, err
		}
		if w.ID == "" || w.Required == nil || seen[w.ID] {
			return nil, fmt.Errorf("item %q has no id or required flag, or is repeated", w.ID)
		}
		seen[w.ID] = true
		switch w.State {
		case StateComplete, StateReady, StateBlocked, StateUnknown:
		default:
			return nil, fmt.Errorf("item %s has unknown state %q", w.ID, w.State)
		}
		if (w.State == StateReady) != listed[w.ID] {
			return nil, fmt.Errorf("item %s: state %q disagrees with the ready list", w.ID, w.State)
		}
		items = append(items, item{id: w.ID, required: *w.Required, state: w.State, raw: raw})
	}
	for id := range listed {
		if !seen[id] {
			return nil, fmt.Errorf("ready list names %s, which is not an item", id)
		}
	}
	return items, nil
}

// Provenance is the publication's provenance, aged against now.
func (p *Publication) Provenance(now time.Time) Provenance {
	prov := p.prov
	if at := prov.Observation.CapturedAt; at != nil {
		age := int64(now.Sub(*at) / time.Second)
		prov.AgeSeconds = &age
	}
	return prov
}

// find resolves an epic by name or by its root issue ("owner/repo#N").
func (p *Publication) find(key string) (*epicEntry, error) {
	key = strings.TrimSpace(key)
	for _, e := range p.epics {
		if strings.EqualFold(e.epic.Name, key) || (e.epic.Issue != nil && strings.EqualFold(e.epic.Issue.String(), key)) {
			return e, nil
		}
	}
	return nil, fmt.Errorf("%w: %q", ErrEpicNotFound, key)
}

// EpicStatus answers "what is the status of epic X".
func (p *Publication) EpicStatus(key string, now time.Time) (*EpicStatus, error) {
	e, err := p.find(key)
	if err != nil {
		return nil, err
	}
	return &EpicStatus{Epic: e.epic, Readiness: e.readiness, Health: e.health, Provenance: p.Provenance(now)}, nil
}

// ReadyWorkItems answers "what work is ready now", for one epic (by name or
// root issue) or, with an empty key, for every active epic.
func (p *Publication) ReadyWorkItems(key string, requiredOnly bool, now time.Time) (*ReadyWorkItems, error) {
	var epics []*epicEntry
	if strings.TrimSpace(key) != "" {
		e, err := p.find(key)
		if err != nil {
			return nil, err
		}
		epics = []*epicEntry{e}
	} else {
		for _, e := range p.epics {
			if e.epic.Lifecycle == LifecycleActive {
				epics = append(epics, e)
			}
		}
	}
	out := &ReadyWorkItems{RequiredOnly: requiredOnly, Epics: []ReadyEpic{}, Provenance: p.Provenance(now)}
	for _, e := range epics {
		re := ReadyEpic{Epic: e.epic, Source: e.source, Items: []json.RawMessage{}}
		for _, it := range e.items {
			if it.state == StateReady && (it.required || !requiredOnly) {
				re.Items = append(re.Items, it.raw)
			}
		}
		out.Epics = append(out.Epics, re)
	}
	return out, nil
}

// Epics lists the published epics, sorted by name.
func (p *Publication) Epics() []Epic {
	out := make([]Epic, 0, len(p.epics))
	for _, e := range p.epics {
		out = append(out, e.epic)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Reader serves the current publication, re-verifying only when the
// roadmap-state checkout moves.
type Reader struct {
	src FileSource

	mu sync.Mutex
	// The answer for one revision, good or bad: a publication that failed
	// verification is re-read only when the checkout moves.
	cachedRev string
	cached    *Publication
	cachedErr error
}

// NewReader wraps a file source.
func NewReader(src FileSource) *Reader { return &Reader{src: src} }

// Current returns the verified publication at the checkout's current commit.
// A publication that fails verification is never served, and neither is the
// previously cached one: the cache answers only for the commit it was read at.
func (r *Reader) Current() (*Publication, error) {
	if r == nil || r.src == nil {
		return nil, unavailable("no roadmap-state source is configured")
	}
	rev, err := r.src.Revision()
	if err != nil {
		return nil, unavailable("roadmap-state checkout: %v", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cachedRev != "" && r.cachedRev == rev {
		return r.cached, r.cachedErr
	}
	files, readRev, err := r.src.ReadFiles(PublicationFile, SnapshotFile, ReadySetFile, HealthFile)
	if err != nil {
		// Not cached: a read error is about the checkout, not the revision.
		return nil, unavailable("roadmap-state checkout: %v", err)
	}
	pub, err := Parse(files, readRev)
	r.cachedRev, r.cached, r.cachedErr = readRev, pub, err
	return pub, err
}
