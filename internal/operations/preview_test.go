// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package operations

import "testing"

func TestGeneratePreviewTagUnique(t *testing.T) {
	first := GeneratePreviewTag("main")
	second := GeneratePreviewTag("main")
	if first == second {
		t.Errorf("GeneratePreviewTag(%q) produced identical tags on successive calls: %q", "main", first)
	}
}

func TestSanitizePreviewTag(t *testing.T) {
	tests := []struct {
		name string
		ref  string
		want string
	}{
		{"simple branch", "feat/my-feature", "feat-my-feature"},
		{"uppercase lowered", "Feat/MyFeature", "feat-myfeature"},
		{"collapses runs of separators", "feat//my___feature", "feat-my-feature"},
		{"trims leading and trailing separators", "/feat/", "feat"},
		{"all-invalid ref falls back", "///", "ref"},
		{"empty ref falls back", "", "ref"},
		{"truncates to 30 chars", "this-is-a-very-long-branch-name-that-exceeds-the-limit", "this-is-a-very-long-branch-nam"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizePreviewTag(tt.ref)
			if got != tt.want {
				t.Errorf("SanitizePreviewTag(%q) = %q, want %q", tt.ref, got, tt.want)
			}
			if len(got) > 30 {
				t.Errorf("SanitizePreviewTag(%q) = %q, exceeds 30 chars", tt.ref, got)
			}
		})
	}
}

func TestPreparePreviewDeployInput(t *testing.T) {
	t.Run("existing image mode requires image_tag", func(t *testing.T) {
		input := map[string]string{}
		if err := PreparePreviewDeployInput(input); err == nil {
			t.Error("expected error when neither git_ref nor image_tag is set")
		}
	})

	t.Run("existing image mode passes through explicit image_tag", func(t *testing.T) {
		input := map[string]string{"image_tag": "1.2.3"}
		if err := PreparePreviewDeployInput(input); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if input["image_tag"] != "1.2.3" {
			t.Errorf("image_tag = %q, want unchanged", input["image_tag"])
		}
	})

	t.Run("build-from-branch mode requires dockerfile_repo", func(t *testing.T) {
		input := map[string]string{"git_ref": "main"}
		if err := PreparePreviewDeployInput(input); err == nil {
			t.Error("expected error when git_ref is set without dockerfile_repo")
		}
	})

	t.Run("build-from-branch mode auto-generates image_tag", func(t *testing.T) {
		input := map[string]string{"git_ref": "feat/my-feature", "dockerfile_repo": "mctlhq/mctl-api"}
		if err := PreparePreviewDeployInput(input); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if input["image_tag"] == "" {
			t.Error("expected image_tag to be auto-generated")
		}
	})

	t.Run("build-from-branch mode keeps explicit image_tag override", func(t *testing.T) {
		input := map[string]string{"git_ref": "main", "dockerfile_repo": "mctlhq/mctl-api", "image_tag": "custom-tag"}
		if err := PreparePreviewDeployInput(input); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if input["image_tag"] != "custom-tag" {
			t.Errorf("image_tag = %q, want %q (explicit override preserved)", input["image_tag"], "custom-tag")
		}
	})
}
