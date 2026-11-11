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

// Source is a live authority source a checkpoint reads.
type Source string

// Sources.
const (
	SourceIdentity Source = "identity"
	SourceInstall  Source = "install"
	SourceTenant   Source = "tenant"
	SourcePolicy   Source = "policy"
	SourceBudget   Source = "budget"
	SourceApproval Source = "approval"
)

// Checkpoint is one of the three authorization checkpoints.
type Checkpoint int

// Checkpoints: (a) create/update, (b) fire time before the per-fire wi_ is
// created, (c) immediately before each externally observable side effect.
const (
	CheckpointCreateUpdate Checkpoint = iota + 1
	CheckpointFire
	CheckpointSideEffect
)

// LinkState is the resolved state of the SurfaceIdentityLink or OAuth
// principal. The zero value is LinkUnknown and is never allowed.
type LinkState int

// Link states.
const (
	LinkUnknown LinkState = iota
	LinkLive
	LinkUnlinked
	LinkExpired
	LinkRevoked
)

// InstallState is the resolved revision state of an opaque install_ref. Its
// real representation is unknown (mctl-telegram has not defined it).
type InstallState int

// Install states.
const (
	InstallUnknown InstallState = iota // zero value: never allowed
	InstallNotRequired
	InstallLive
	InstallRevoked
	InstallExpired
)

// ApprovalBinding is the execution an aar_ is bound to.
type ApprovalBinding struct{ ExecutionID string }

// Inputs are already-resolved facts. Nothing here is read from a store.
type Inputs struct {
	// Unavailable lists sources that could not be read. Any entry yields
	// automation_authority_unavailable: unknown is never allowed.
	Unavailable []Source

	Link             LinkState
	Install          InstallState
	SurfaceMatches   bool
	TenantMember     bool // caller is a live member of the definition's tenant
	TargetExists     bool
	TenantAccessible bool // the named tenant is accessible to the caller
	OwnerMatches     bool // caller is the definition's owner principal
	ChangesOwner     bool // a patch tries to change the owner

	PinnedPolicyVersion string
	LivePolicyVersion   string

	BudgetNeeded      int64
	HeadroomPerRun    int64
	HeadroomPerDay    int64
	HeadroomPerTenant int64

	ApprovalRequired   bool
	ScheduleAsApproval bool
	Approval           *ApprovalBinding
	ThisExecutionID    string
}

// Decision is the outcome of Decide.
type Decision struct {
	Allowed bool
	Code    Code
}

func deny(c Code) Decision { return Decision{Code: c} }

// Decide models the checkpoint rules of docs/automation-contract.md.
//
// Claim class: isolated-model. It is a pure function over resolved facts, it
// is NOT wired to governance.Revalidate or any store, and it has no
// production caller. Wiring is for later slices.
func Decide(cp Checkpoint, in Inputs) Decision {
	if cp < CheckpointCreateUpdate || cp > CheckpointSideEffect {
		return deny(CodeInvalid)
	}
	if len(in.Unavailable) > 0 {
		return deny(CodeAuthorityUnavailable)
	}
	if in.Link != LinkLive || !in.SurfaceMatches || !in.TenantMember ||
		in.Install == InstallRevoked || in.Install == InstallExpired || in.Install == InstallUnknown {
		return deny(CodeIdentityUnlinked)
	}
	if !in.TargetExists || !in.TenantAccessible || !in.OwnerMatches || in.ChangesOwner {
		// Identical to a nonexistent definition: no existence oracle.
		return deny(CodeNotFound)
	}
	if in.PinnedPolicyVersion != in.LivePolicyVersion {
		return deny(CodePolicyDrift)
	}
	if in.BudgetNeeded > in.HeadroomPerRun || in.BudgetNeeded > in.HeadroomPerDay || in.BudgetNeeded > in.HeadroomPerTenant {
		return deny(CodeBudgetExhausted)
	}
	if in.ScheduleAsApproval || (in.Approval != nil &&
		(in.Approval.ExecutionID == "" || in.ThisExecutionID == "" || in.Approval.ExecutionID != in.ThisExecutionID)) {
		return deny(CodeApprovalNotReusable)
	}
	if cp == CheckpointSideEffect && in.ApprovalRequired && in.Approval == nil {
		return deny(CodeApprovalRequired)
	}
	return Decision{Allowed: true}
}
