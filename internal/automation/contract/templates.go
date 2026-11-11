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
	"fmt"

	"github.com/mctlhq/mctl-api/internal/secretscan"
)

// MaxReminderTextBytes bounds reminder.v1 text.
const MaxReminderTextBytes = 2048

// AgentScope names the run scope a template executes under.
type AgentScope string

// Scopes.
const (
	ScopeNone    AgentScope = ""
	ScopeSupport AgentScope = "support"
)

// Template is the server-side binding of a template id. A client never
// supplies any of these fields (docs/automation-contract.md, Templates).
type Template struct {
	ID              string
	ParamsSchema    string
	Capability      string
	Scope           AgentScope
	TaskQueue       string
	WorkflowType    string
	AllowedTriggers []string
	SideEffects     []string
}

// templates is the closed allowlist (templates/v1). Isolated-model: the queue
// and workflow names are contract placeholders, not registered workflows.
var templates = map[string]Template{
	"reminder.v1": {
		ID: "reminder.v1", ParamsSchema: "template-reminder.v1.schema.json",
		Capability: "notify.surface", TaskQueue: "mctl-dev-loop", WorkflowType: "AutomationReminder",
		AllowedTriggers: []string{"at", "schedule"}, SideEffects: []string{"notify.surface"},
	},
	"support.diagnostic-followup.v1": {
		ID: "support.diagnostic-followup.v1", ParamsSchema: "template-support-followup.v1.schema.json",
		Capability: "read.diagnostics", Scope: ScopeSupport, TaskQueue: "mctl-dev-loop", WorkflowType: "AutomationSupportFollowup",
		AllowedTriggers: []string{"at"},
	},
}

// LookupTemplate resolves a template id on the allowlist.
func LookupTemplate(id string) (Template, bool) {
	t, ok := templates[id]
	return t, ok
}

func checkReminderText(params map[string]any) error {
	text, _ := params["text"].(string)
	if len(text) > MaxReminderTextBytes {
		return fail(CodeInvalid, "reminder text exceeds %d bytes", MaxReminderTextBytes)
	}
	if p, found := secretscan.Scan([]byte(text)); found {
		return fail(CodeInvalid, "%s", fmt.Sprintf("reminder text matches secret pattern %s", p))
	}
	return nil
}
