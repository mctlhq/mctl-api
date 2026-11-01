// Package reviewreceipts is a pure Go port of the Tier A review-receipt
// contract (mctl-agents orchestrator/review_receipts.py, ADR 025): sealed
// ReviewRequest and ReviewReceipt documents, strict parsing, identity
// recomputation and the review gate. It performs no I/O.
package reviewreceipts

import "regexp"

const (
	APIVersion      = "review.mctl.ai/v1alpha1"
	RequestKind     = "ReviewRequest"
	ReceiptKind     = "ReviewReceipt"
	RequestIDPrefix = "rr_"
	ReceiptIDPrefix = "rc_"

	SubjectSpikeReport = "spike_report"
	SubjectProposal    = "proposal"

	SpikeDigestVersion = "spike_report_digest_v1"

	ModeWorker = "worker"
	ModeManual = "manual"

	AssuranceIndependent = "independent"
	AssuranceAdvisory    = "advisory"
	// AssuranceAny is a required-assurance value only.
	AssuranceAny = "any"

	RubricSpike    = "spike_v1"
	RubricProposal = "proposal_v1"

	// Bounds.
	MaxStr    = 256
	MaxActors = 64
)

// Gate answers, byte for byte the Tier A constants.
const (
	GateSatisfied        = "satisfied"
	GateStale            = "stale"
	GateMissing          = "missing"
	GateUnknown          = "unknown"
	GateAdvisoryOnly     = "advisory_only"
	GateNotIndependent   = "not_independent"
	GateChangesRequested = "changes_requested"
	GateNeedsHuman       = "needs_human"
	GateUnobservable     = "unobservable"
)

var (
	outcomes        = []string{"PASS", "CHANGES_REQUESTED", "NEEDS_HUMAN", "UNOBSERVABLE"}
	criterionStatus = []string{"met", "unmet", "unobserved"}
	modes           = []string{ModeWorker, ModeManual}
	subjectKinds    = []string{SubjectProposal, SubjectSpikeReport}
	rubricNames     = []string{RubricProposal, RubricSpike}
	outcomeToGate   = map[string]string{
		"PASS":              GateSatisfied,
		"CHANGES_REQUESTED": GateChangesRequested,
		"NEEDS_HUMAN":       GateNeedsHuman,
		"UNOBSERVABLE":      GateUnobservable,
	}
	rubrics = map[string][]string{
		RubricSpike: {
			"hypothesis_stated",
			"method_described",
			"measurements_present",
			"measurements_reproducible",
			"claims_traceable_to_measurements",
			"limitations_stated",
		},
		RubricProposal: {
			"scope_bounded",
			"contracts_specified",
			"acceptance_testable",
			"rollback_defined",
			"matches_issue",
		},
	}
	rubricForSubject = map[string]string{SubjectSpikeReport: RubricSpike, SubjectProposal: RubricProposal}
)

func anchored(p string) *regexp.Regexp { return regexp.MustCompile(`^(?:` + p + `)$`) }

var (
	shaRE         = anchored(`[0-9a-f]{40}(?:[0-9a-f]{24})?`)
	digestRE      = anchored(`sha256:[0-9a-f]{64}`)
	repoRE        = anchored(`[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}`)
	slugRE        = anchored(`[a-z0-9][a-z0-9._-]{0,127}`)
	serviceRE     = anchored(`[A-Za-z0-9][A-Za-z0-9._-]{0,127}`)
	executionIDRE = anchored(`(?:we_[0-9a-f]{16,64}|ex-[0-9a-f]{16})`)
	evidenceIDRE  = anchored(`ev-[0-9a-f]{16}`)
	createdAtRE   = anchored(`[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z`)
	grantRefRE    = anchored(`aar_[A-Za-z0-9_-]{1,124}`)
	requestIDRE   = anchored(`rr_[0-9a-f]{16}`)
)

// ReviewSubject is the exact, digest-bound thing under review.
type ReviewSubject struct {
	Kind string

	// spike_report fields
	Repository      string
	ReportRoot      string
	ReportPath      string
	SourceSHA       string
	BaseSHA         string
	HeadSHA         string
	InventoryDigest string
	DigestVersion   string

	// proposal fields
	Service       string
	Slug          string
	GitopsCommit  string
	ContentDigest string
	ApprovalRef   string
}

// SubjectIdentity is what is under review, independent of which bytes.
type SubjectIdentity [4]string

// SubjectBinding is the bytes a receipt is valid for.
type SubjectBinding struct {
	Kind            string
	Repository      string
	ReportRoot      string
	ReportPath      string
	SourceSHA       string
	BaseSHA         string
	HeadSHA         string
	InventoryDigest string
	DigestVersion   string
	Service         string
	Slug            string
	ContentDigest   string
}

// Identity mirrors Tier A ReviewSubject.identity().
func (s ReviewSubject) Identity() SubjectIdentity {
	if s.Kind == SubjectSpikeReport {
		return SubjectIdentity{s.Kind, s.Repository, s.ReportRoot, s.ReportPath}
	}
	return SubjectIdentity{s.Kind, s.Service, s.Slug, ""}
}

// Binding mirrors Tier A ReviewSubject.binding(): a proposal's gitops_commit
// and approval_ref are provenance only.
func (s ReviewSubject) Binding() SubjectBinding {
	if s.Kind == SubjectProposal {
		return SubjectBinding{Kind: s.Kind, Service: s.Service, Slug: s.Slug, ContentDigest: s.ContentDigest}
	}
	return SubjectBinding{
		Kind: s.Kind, Repository: s.Repository, ReportRoot: s.ReportRoot, ReportPath: s.ReportPath,
		SourceSHA: s.SourceSHA, BaseSHA: s.BaseSHA, HeadSHA: s.HeadSHA,
		InventoryDigest: s.InventoryDigest, DigestVersion: s.DigestVersion,
	}
}

// Dict mirrors Tier A ReviewSubject.to_dict().
func (s ReviewSubject) Dict() map[string]any {
	out := map[string]any{"kind": s.Kind}
	if s.Kind == SubjectSpikeReport {
		out["repository"] = s.Repository
		out["report_root"] = s.ReportRoot
		out["report_path"] = s.ReportPath
		out["source_sha"] = s.SourceSHA
		out["base_sha"] = s.BaseSHA
		out["head_sha"] = s.HeadSHA
		out["inventory_digest"] = s.InventoryDigest
		out["digest_version"] = s.DigestVersion
		return out
	}
	out["service"] = s.Service
	out["slug"] = s.Slug
	out["gitops_commit"] = s.GitopsCommit
	out["content_digest"] = s.ContentDigest
	if s.ApprovalRef != "" {
		out["approval_ref"] = s.ApprovalRef
	}
	return out
}

// Criterion is one rubric criterion and its status.
type Criterion struct {
	ID     string
	Status string
}

// ArtifactRef is an immutable ref to a generated artifact, never its bytes.
type ArtifactRef struct {
	Name        string
	Kind        string
	ContentHash string
}

// ReviewRequest is a request to review one exact subject. Build with
// SealRequest or ParseRequest.
type ReviewRequest struct {
	Subject              ReviewSubject
	Rubric               string
	Mode                 string
	AuthorActors         []string
	Nonce                string
	AuthoringExecutionID string
	AuthoringAttemptIDs  []string
	AuthoringLineageRoot string
	CreatedAt            string
	ContentHash          string
	RequestID            string
}

// ReviewReceipt is the answer to a ReviewRequest. Build with SealReceipt or
// ParseReceipt.
type ReviewReceipt struct {
	RequestID           string
	Subject             ReviewSubject
	Rubric              string
	Outcome             string
	Criteria            []Criterion
	Mode                string
	Nonce               string
	FindingsRef         ArtifactRef
	Assurance           string
	ReviewerActor       string
	ReviewerExecutionID string
	AttemptID           string
	LineageRoot         string
	EvidenceRef         string
	CreatedAt           string
	ContentHash         string
	ReceiptID           string
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// Key is the canonical JSON of the identity, equal for two identities if and
// only if they are equal. Stores index it so SQL and Go agree on equality.
func (i SubjectIdentity) Key() string {
	return string(canonicalJSON([]string{i[0], i[1], i[2], i[3]}))
}

// Key is the canonical JSON of the binding, equal for two bindings if and
// only if they are equal.
func (b SubjectBinding) Key() string {
	return string(canonicalJSON(map[string]any{
		"kind":             b.Kind,
		"repository":       b.Repository,
		"report_root":      b.ReportRoot,
		"report_path":      b.ReportPath,
		"source_sha":       b.SourceSHA,
		"base_sha":         b.BaseSHA,
		"head_sha":         b.HeadSHA,
		"inventory_digest": b.InventoryDigest,
		"digest_version":   b.DigestVersion,
		"service":          b.Service,
		"slug":             b.Slug,
		"content_digest":   b.ContentDigest,
	}))
}
