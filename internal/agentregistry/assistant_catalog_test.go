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

package agentregistry

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// assistantSpec builds a minimal materialized TelegramAssistant document.
func assistantSpec(name, version, visibility, status string) string {
	return `{"apiVersion":"assistants.mctl.ai/v1alpha1","kind":"TelegramAssistant",` +
		`"metadata":{"name":"` + name + `","title":"T","description":"D","version":"` + version + `",` +
		`"owner":"mctl","visibility":"` + visibility + `","status":"` + status + `","tags":["hr"],"examples":["hi"]},` +
		`"spec":{"instructions":{"text":"SECRET-INSTRUCTIONS"},"variables":[],"intents":[],` +
		`"defaults":{"mode":"draft","limits":{"maxReplyChars":500},"disclosure":{"policy":"always","text":"x"}}}}`
}

func newAssistantVersion(name, version, visibility, status string) *DefinitionVersion {
	return &DefinitionVersion{
		Agent:    name,
		Version:  version,
		SpecJSON: assistantSpec(name, version, visibility, status),
		Owner:    "mctl-telegram",
		SourceManifest: SourceManifest{
			Repo: "mctlhq/mctl-telegram", Path: "assistants/" + name + "/assistant.yaml",
			GitSHA: "deadbeef", ContentHash: "sha256:assistant",
		},
	}
}

func TestDefinitionKind(t *testing.T) {
	for spec, want := range map[string]string{
		`{"kind":"TelegramAssistant"}`: KindTelegramAssistant,
		`{"kind":"AgentDefinition"}`:   "AgentDefinition",
		`{}`:                           "",
		`{"kind":1}`:                   "",
		`[1,2]`:                        "",
		`not json`:                     "",
	} {
		if got := DefinitionKind(spec); got != want {
			t.Errorf("DefinitionKind(%s) = %q, want %q", spec, got, want)
		}
	}
}

// TestPublishDefinitionVersion_ProfileRangeStillRequiredForOtherKinds pins
// that the profile-less exemption is the TelegramAssistant kind's alone.
// Every rejection here happens before the pool, so a zero-value Store
// reaches it.
func TestPublishDefinitionVersion_ProfileRangeStillRequiredForOtherKinds(t *testing.T) {
	s := &Store{}
	for _, spec := range []string{`{"kind":"AgentDefinition"}`, `{}`, `{"kind":"telegramassistant"}`} {
		d := newDefinitionVersion("issue-investigator", "1.0.0", "")
		d.SpecJSON = spec
		if _, err := s.PublishDefinitionVersion(context.Background(), d); !errors.Is(err, ErrInvalidRange) {
			t.Errorf("spec %s with no profile_range: expected ErrInvalidRange, got %v", spec, err)
		}
	}
}

func TestPublishDefinitionVersion_TelegramAssistantRejections(t *testing.T) {
	s := &Store{}
	withRange := newAssistantVersion("hr-recruiter", "0.1.0", "public", "active")
	withRange.ProfileRange = ">=1.0.0"
	if _, err := s.PublishDefinitionVersion(context.Background(), withRange); !errors.Is(err, ErrInvalidRange) {
		t.Errorf("a TelegramAssistant with a profile_range: expected ErrInvalidRange, got %v", err)
	}

	cases := map[string]*DefinitionVersion{
		"tenant visibility":  newAssistantVersion("hr-recruiter", "0.1.0", "tenant", "active"),
		"unknown status":     newAssistantVersion("hr-recruiter", "0.1.0", "public", "live"),
		"name mismatch":      newAssistantVersion("hr-recruiter", "0.1.0", "public", "active"),
		"version mismatch":   newAssistantVersion("hr-recruiter", "0.1.0", "public", "active"),
		"malformed metadata": newAssistantVersion("hr-recruiter", "0.1.0", "public", "active"),
	}
	cases["name mismatch"].Agent = "other"
	cases["version mismatch"].Version = "0.2.0"
	cases["malformed metadata"].SpecJSON = `{"kind":"TelegramAssistant","metadata":{"tags":"hr"}}`
	for name, d := range cases {
		if _, err := s.PublishDefinitionVersion(context.Background(), d); !errors.Is(err, ErrInvalidSpec) {
			t.Errorf("%s: expected ErrInvalidSpec, got %v", name, err)
		}
	}
}

func TestPublishDefinitionVersion_TelegramAssistantWithoutProfile(t *testing.T) {
	s := newV1Alpha2TestStore(t)
	ctx := context.Background()
	if _, err := s.CreateDefinition(ctx, "hr-recruiter", "", ""); err != nil {
		t.Fatalf("create definition: %v", err)
	}
	stored, err := s.PublishDefinitionVersion(ctx, newAssistantVersion("hr-recruiter", "0.1.0", "public", "active"))
	if err != nil {
		t.Fatalf("publish TelegramAssistant without profile_range: %v", err)
	}
	if stored.ProfileRange != "" || stored.Lifecycle != LifecyclePublished {
		t.Fatalf("unexpected stored row: range %q lifecycle %q", stored.ProfileRange, stored.Lifecycle)
	}

	got, err := s.ListDefinitionVersionsByKind(ctx, KindTelegramAssistant)
	if err != nil {
		t.Fatalf("list by kind: %v", err)
	}
	if len(got) != 1 || got[0].Agent != "hr-recruiter" {
		t.Fatalf("expected the one assistant, got %+v", got)
	}
}

// TestBindings_RefuseTelegramAssistant: a profile-less definition is
// refused by every path that would pair it with a profile, as such, and
// never reaches the range parse its empty range would fail.
func TestBindings_RefuseTelegramAssistant(t *testing.T) {
	s := newV1Alpha2TestStore(t)
	ctx := context.Background()
	if _, err := s.CreateDefinition(ctx, "hr-recruiter", "", ""); err != nil {
		t.Fatalf("create definition: %v", err)
	}
	if _, err := s.PublishDefinitionVersion(ctx, newAssistantVersion("hr-recruiter", "0.1.0", "public", "active")); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if _, err := s.PublishProfileVersion(ctx, newProfileVersion("standard-investigate", "2.1.0")); err != nil {
		t.Fatalf("publish profile: %v", err)
	}

	_, err := s.CreateBinding(ctx, CreateBindingRequest{
		Agent: "hr-recruiter", Environment: EnvironmentShadow,
		DefinitionVersion: "0.1.0", Profile: "standard-investigate", ProfileVersion: "2.1.0", Actor: "tester",
	})
	if !errors.Is(err, ErrProfilelessDefinition) {
		t.Fatalf("CreateBinding: expected ErrProfilelessDefinition, got %v", err)
	}
	// A profile that does not exist still reports the definition's kind,
	// not the missing profile.
	_, err = s.CreateBinding(ctx, CreateBindingRequest{
		Agent: "hr-recruiter", Environment: EnvironmentShadow,
		DefinitionVersion: "0.1.0", Profile: "nope", ProfileVersion: "1.0.0", Actor: "tester",
	})
	if !errors.Is(err, ErrProfilelessDefinition) {
		t.Fatalf("CreateBinding with a missing profile: expected ErrProfilelessDefinition, got %v", err)
	}
	for _, pv := range []string{"2.1.0", ""} {
		if _, err := s.ResolveExplicit(ctx, "hr-recruiter", "0.1.0", "standard-investigate", pv); !errors.Is(err, ErrProfilelessDefinition) {
			t.Fatalf("ResolveExplicit(profileVersion=%q): expected ErrProfilelessDefinition, got %v", pv, err)
		}
	}
}

func TestValidateBindingPair_RefusesProfileless(t *testing.T) {
	def := newAssistantVersion("hr-recruiter", "0.1.0", "public", "active")
	def.Lifecycle = LifecyclePublished
	prof := newProfileVersion("standard-investigate", "2.1.0")
	prof.Lifecycle = LifecyclePublished
	if err := validateBindingPairNotDisabled(def, prof); !errors.Is(err, ErrProfilelessDefinition) {
		t.Fatalf("expected ErrProfilelessDefinition, got %v", err)
	}
	if _, err := buildResolvedBinding(nil, def, prof); !errors.Is(err, ErrProfilelessDefinition) {
		t.Fatalf("buildResolvedBinding: expected ErrProfilelessDefinition, got %v", err)
	}
	if !strings.Contains(ErrProfilelessDefinition.Error(), "execution profile") {
		t.Fatal("the sentinel must name what is refused")
	}
}

func TestSortByAgentThenVersionDesc(t *testing.T) {
	versions := []DefinitionVersion{
		{Agent: "b", Version: "1.0.0"}, {Agent: "a", Version: "0.9.0"},
		{Agent: "a", Version: "0.10.0"}, {Agent: "a", Version: "0.2.1"},
	}
	sortByAgentThenVersionDesc(versions)
	var got []string
	for _, v := range versions {
		got = append(got, v.Agent+"@"+v.Version)
	}
	if want := "a@0.10.0,a@0.9.0,a@0.2.1,b@1.0.0"; strings.Join(got, ",") != want {
		t.Fatalf("got %s, want %s", strings.Join(got, ","), want)
	}
}
