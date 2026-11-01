package reviewreceipts

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// ---- shared validation helpers (used by both parsing and sealing) ----

func checkStr(v any, where string, pattern *regexp.Regexp, allowEmpty bool) (string, error) {
	s, ok := v.(string)
	if !ok || (s == "" && !allowEmpty) {
		return "", newErr(CodeMalformed, where+" must be a non-empty string")
	}
	return checkStrValue(s, where, pattern, allowEmpty)
}

func checkStrValue(s, where string, pattern *regexp.Regexp, allowEmpty bool) (string, error) {
	if s == "" && !allowEmpty {
		return "", newErr(CodeMalformed, where+" must be a non-empty string")
	}
	if utf8.RuneCountInString(s) > MaxStr {
		return "", newErr(CodeMalformed, fmt.Sprintf("%s exceeds %d characters", where, MaxStr))
	}
	if s != "" && pattern != nil && !pattern.MatchString(s) {
		return "", newErr(CodeMalformed, where+" has an invalid shape")
	}
	return s, nil
}

func checkChoice(v any, allowed []string, where string) (string, error) {
	s, ok := v.(string)
	if !ok || !contains(allowed, s) {
		return "", newErr(CodeMalformed, fmt.Sprintf("%s must be one of %v", where, allowed))
	}
	return s, nil
}

func checkStrList(v any, where string) ([]string, error) {
	list, ok := v.([]any)
	if !ok || len(list) > MaxActors {
		return nil, newErr(CodeMalformed, fmt.Sprintf("%s must be a list of at most %d strings", where, MaxActors))
	}
	out := make([]string, 0, len(list))
	for _, e := range list {
		s, err := checkStr(e, where, nil, false)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return sortedSet(out), nil
}

func asMap(v any, where string) (map[string]any, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, newErr(CodeMalformed, where+" must be a mapping")
	}
	return m, nil
}

func checkKeys(m map[string]any, allowed map[string]struct{}, where string) error {
	var unknown []string
	for k := range m {
		if _, ok := allowed[k]; !ok {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return newErr(CodeUnknownKey, fmt.Sprintf("%s: unknown key(s) %s", where, strings.Join(unknown, ",")))
	}
	return nil
}

func keySet(keys ...string) map[string]struct{} {
	out := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		out[k] = struct{}{}
	}
	return out
}

func checkAPI(m map[string]any, kind string) error {
	if m["api_version"] != APIVersion || m["kind"] != kind {
		return newErr(CodeMalformed, "expected "+APIVersion+" "+kind)
	}
	return nil
}

func createdAt(m map[string]any) (string, error) {
	v, ok := m["created_at"]
	if !ok {
		v = ""
	}
	return checkStr(v, "created_at", createdAtRE, true)
}

func getOr(m map[string]any, key string) any {
	if v, ok := m[key]; ok {
		return v
	}
	return ""
}

func decodeObject(data []byte, where string) (map[string]any, error) {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, newErr(CodeMalformed, where+" is not valid JSON")
	}
	return asMap(v, where)
}

// ---- subject ----

var (
	spikeFields    = []string{"repository", "report_root", "report_path", "source_sha", "base_sha", "head_sha", "inventory_digest", "digest_version"}
	proposalFields = []string{"service", "slug", "gitops_commit", "content_digest", "approval_ref"}
)

func subjectKeys() map[string]struct{} {
	all := append([]string{"kind"}, spikeFields...)
	return keySet(append(all, proposalFields...)...)
}

func (s *ReviewSubject) fieldPtr(name string) *string {
	switch name {
	case "repository":
		return &s.Repository
	case "report_root":
		return &s.ReportRoot
	case "report_path":
		return &s.ReportPath
	case "source_sha":
		return &s.SourceSHA
	case "base_sha":
		return &s.BaseSHA
	case "head_sha":
		return &s.HeadSHA
	case "inventory_digest":
		return &s.InventoryDigest
	case "digest_version":
		return &s.DigestVersion
	case "service":
		return &s.Service
	case "slug":
		return &s.Slug
	case "gitops_commit":
		return &s.GitopsCommit
	case "content_digest":
		return &s.ContentDigest
	case "approval_ref":
		return &s.ApprovalRef
	}
	return nil
}

func subjectFromValue(v any) (ReviewSubject, error) {
	m, err := asMap(v, "subject")
	if err != nil {
		return ReviewSubject{}, err
	}
	if err := checkKeys(m, subjectKeys(), "subject"); err != nil {
		return ReviewSubject{}, err
	}
	kind, err := checkChoice(m["kind"], subjectKinds, "subject.kind")
	if err != nil {
		return ReviewSubject{}, err
	}
	allowed, other := spikeFields, proposalFields
	if kind == SubjectProposal {
		allowed, other = proposalFields, spikeFields
	}
	var extra []string
	for _, k := range other {
		if _, ok := m[k]; ok {
			extra = append(extra, k)
		}
	}
	if len(extra) > 0 {
		sort.Strings(extra)
		return ReviewSubject{}, newErr(CodeBadSubject, fmt.Sprintf("%s subject cannot carry %s", kind, strings.Join(extra, ",")))
	}
	s := ReviewSubject{Kind: kind}
	for _, name := range allowed {
		var val string
		if name == "approval_ref" {
			val, err = checkStr(getOr(m, name), "subject.approval_ref", grantRefRE, true)
		} else {
			val, err = checkStr(m[name], "subject."+name, nil, false)
		}
		if err != nil {
			return ReviewSubject{}, err
		}
		*s.fieldPtr(name) = val
	}
	if err := s.validateSemantics(); err != nil {
		return ReviewSubject{}, err
	}
	return s, nil
}

// ParseSubject strictly decodes one subject document.
func ParseSubject(data []byte) (ReviewSubject, error) {
	v, err := decodeObject(data, "subject")
	if err != nil {
		return ReviewSubject{}, err
	}
	return subjectFromValue(v)
}

func checkPath(p string) error {
	if p == "" {
		return fmt.Errorf("empty path")
	}
	if strings.ContainsAny(p, "\\\x00") {
		return fmt.Errorf("path %q holds a backslash or NUL", p)
	}
	if strings.HasPrefix(p, "/") {
		return fmt.Errorf("path %q is absolute", p)
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return fmt.Errorf("path %q has an empty, '.' or '..' segment", p)
		}
	}
	return nil
}

// Validate checks the subject the way parsing does: fields must fit the
// kind, respect the bounds, and have the right shapes.
func (s ReviewSubject) Validate() error {
	if !contains(subjectKinds, s.Kind) {
		return newErr(CodeBadSubject, "unknown subject kind")
	}
	allowed, other := spikeFields, proposalFields
	if s.Kind == SubjectProposal {
		allowed, other = proposalFields, spikeFields
	}
	for _, k := range other {
		if *s.fieldPtr(k) != "" {
			return newErr(CodeBadSubject, fmt.Sprintf("%s subject cannot carry %s", s.Kind, k))
		}
	}
	for _, name := range allowed {
		val := *s.fieldPtr(name)
		var err error
		if name == "approval_ref" {
			_, err = checkStrValue(val, "subject.approval_ref", grantRefRE, true)
		} else {
			_, err = checkStrValue(val, "subject."+name, nil, false)
		}
		if err != nil {
			return err
		}
	}
	return s.validateSemantics()
}

func (s ReviewSubject) validateSemantics() error {
	if s.Kind == SubjectSpikeReport {
		if !repoRE.MatchString(s.Repository) {
			return newErr(CodeBadSubject, "repository must be owner/name")
		}
		if err := checkPath(s.ReportRoot); err != nil {
			return newErr(CodeBadSubject, err.Error())
		}
		if err := checkPath(s.ReportPath); err != nil {
			return newErr(CodeBadSubject, err.Error())
		}
		if !strings.HasSuffix(s.ReportPath, ".md") {
			return newErr(CodeBadSubject, "report_path must be a .md file")
		}
		for name, v := range map[string]string{"source_sha": s.SourceSHA, "base_sha": s.BaseSHA, "head_sha": s.HeadSHA} {
			if !shaRE.MatchString(v) {
				return newErr(CodeBadSubject, name+" must be a full lowercase commit SHA")
			}
		}
		if !digestRE.MatchString(s.InventoryDigest) {
			return newErr(CodeBadSubject, "inventory_digest must be sha256:<64 hex>")
		}
		if s.DigestVersion != SpikeDigestVersion {
			return newErr(CodeBadSubject, "digest_version must be "+SpikeDigestVersion)
		}
		return nil
	}
	if !serviceRE.MatchString(s.Service) || !slugRE.MatchString(s.Slug) {
		return newErr(CodeBadSubject, "service and slug have an invalid shape")
	}
	if !shaRE.MatchString(s.GitopsCommit) {
		return newErr(CodeBadSubject, "gitops_commit must be a full lowercase commit SHA")
	}
	if !digestRE.MatchString(s.ContentDigest) {
		return newErr(CodeBadSubject, "content_digest must be sha256:<64 hex>")
	}
	return nil
}

// ---- request ----

var requestKeys = keySet("api_version", "kind", "request_id", "content_hash", "subject", "rubric", "mode", "author_actors",
	"authoring_execution_id", "authoring_attempt_ids", "authoring_lineage_root", "nonce", "created_at")

// Validate applies the request rules shared by parsing and sealing.
func (r ReviewRequest) Validate() error {
	if err := r.Subject.Validate(); err != nil {
		return err
	}
	if r.Rubric != rubricForSubject[r.Subject.Kind] {
		return newErr(CodeRubricMismatch, fmt.Sprintf("rubric %q does not fit %s", r.Rubric, r.Subject.Kind))
	}
	if !contains(modes, r.Mode) {
		return newErr(CodeMalformed, fmt.Sprintf("mode must be one of %v", modes))
	}
	if _, err := checkStrValue(r.Nonce, "nonce", nil, false); err != nil {
		return err
	}
	// A worker request without authoring_execution_id is representable: the
	// gate answers unknown for it.
	if r.AuthoringExecutionID != "" {
		if _, err := checkStrValue(r.AuthoringExecutionID, "authoring_execution_id", executionIDRE, false); err != nil {
			return err
		}
	}
	if len(r.AuthorActors) > MaxActors || len(r.AuthoringAttemptIDs) > MaxActors {
		return newErr(CodeMalformed, fmt.Sprintf("actor and attempt lists hold at most %d entries", MaxActors))
	}
	for _, v := range r.AuthorActors {
		if _, err := checkStrValue(v, "author_actors", nil, false); err != nil {
			return err
		}
	}
	for _, v := range r.AuthoringAttemptIDs {
		if _, err := checkStrValue(v, "authoring_attempt_ids", nil, false); err != nil {
			return err
		}
	}
	if _, err := checkStrValue(r.AuthoringLineageRoot, "authoring_lineage_root", nil, true); err != nil {
		return err
	}
	if _, err := checkStrValue(r.CreatedAt, "created_at", createdAtRE, true); err != nil {
		return err
	}
	return nil
}

// ParseRequest strictly decodes a request and, when it carries a
// content_hash or request_id, recomputes and verifies them.
func ParseRequest(data []byte) (ReviewRequest, error) {
	m, err := decodeObject(data, "request")
	if err != nil {
		return ReviewRequest{}, err
	}
	return requestFromMap(m)
}

func requestFromMap(m map[string]any) (ReviewRequest, error) {
	if err := checkKeys(m, requestKeys, "request"); err != nil {
		return ReviewRequest{}, err
	}
	if err := checkAPI(m, RequestKind); err != nil {
		return ReviewRequest{}, err
	}
	var r ReviewRequest
	var err error
	if r.Subject, err = subjectFromValue(m["subject"]); err != nil {
		return ReviewRequest{}, err
	}
	if r.Rubric, err = checkChoice(m["rubric"], rubricNames, "rubric"); err != nil {
		return ReviewRequest{}, err
	}
	if r.Mode, err = checkChoice(m["mode"], modes, "mode"); err != nil {
		return ReviewRequest{}, err
	}
	if r.AuthorActors, err = checkStrList(orEmptyList(m, "author_actors"), "author_actors"); err != nil {
		return ReviewRequest{}, err
	}
	if r.Nonce, err = checkStr(m["nonce"], "nonce", nil, false); err != nil {
		return ReviewRequest{}, err
	}
	if r.AuthoringExecutionID, err = checkStr(getOr(m, "authoring_execution_id"), "authoring_execution_id", nil, true); err != nil {
		return ReviewRequest{}, err
	}
	if r.AuthoringAttemptIDs, err = checkStrList(orEmptyList(m, "authoring_attempt_ids"), "authoring_attempt_ids"); err != nil {
		return ReviewRequest{}, err
	}
	if r.AuthoringLineageRoot, err = checkStr(getOr(m, "authoring_lineage_root"), "authoring_lineage_root", nil, true); err != nil {
		return ReviewRequest{}, err
	}
	if r.CreatedAt, err = createdAt(m); err != nil {
		return ReviewRequest{}, err
	}
	if r.ContentHash, err = checkStr(getOr(m, "content_hash"), "content_hash", nil, true); err != nil {
		return ReviewRequest{}, err
	}
	if r.RequestID, err = checkStr(getOr(m, "request_id"), "request_id", nil, true); err != nil {
		return ReviewRequest{}, err
	}
	if err := r.Validate(); err != nil {
		return ReviewRequest{}, err
	}
	if r.ContentHash != "" || r.RequestID != "" {
		if err := checkIdentity(r.ContentHash, r.RequestID, sealHash(r.payload()), RequestIDPrefix); err != nil {
			return ReviewRequest{}, err
		}
	}
	return r, nil
}

func orEmptyList(m map[string]any, key string) any {
	if v, ok := m[key]; ok {
		return v
	}
	return []any{}
}

// ---- receipt ----

var receiptKeys = keySet("api_version", "kind", "receipt_id", "content_hash", "request_id", "subject", "rubric", "outcome",
	"criteria", "findings_ref", "mode", "assurance", "reviewer_actor", "reviewer_execution_id", "attempt_id",
	"lineage_root", "nonce", "evidence_ref", "created_at")

// Validate applies the receipt rules shared by parsing and sealing,
// including the outcome rules.
func (r ReviewReceipt) Validate() error {
	if err := r.Subject.Validate(); err != nil {
		return err
	}
	if !contains(outcomes, r.Outcome) {
		return newErr(CodeMalformed, fmt.Sprintf("outcome must be one of %v", outcomes))
	}
	if !contains(modes, r.Mode) {
		return newErr(CodeMalformed, fmt.Sprintf("mode must be one of %v", modes))
	}
	if r.Rubric != rubricForSubject[r.Subject.Kind] {
		return newErr(CodeRubricMismatch, fmt.Sprintf("rubric %q does not fit %s", r.Rubric, r.Subject.Kind))
	}
	want := AssuranceIndependent
	if r.Mode == ModeManual {
		want = AssuranceAdvisory
	}
	if r.Assurance != want {
		return newErr(CodeMalformed, "assurance must be advisory for manual mode and independent for worker")
	}
	required := rubrics[r.Rubric]
	seen := map[string]bool{}
	for _, c := range r.Criteria {
		if seen[c.ID] || !contains(required, c.ID) {
			return newErr(CodeMalformed, "criteria must be distinct ids of the rubric")
		}
		seen[c.ID] = true
	}
	for _, c := range r.Criteria {
		if !contains(criterionStatus, c.Status) {
			return newErr(CodeMalformed, fmt.Sprintf("criterion.status must be one of %v", criterionStatus))
		}
	}
	switch r.Outcome {
	case "PASS":
		allMet := len(r.Criteria) == len(required)
		for _, c := range r.Criteria {
			if c.Status != "met" {
				allMet = false
			}
		}
		if !allMet {
			return newErr(CodePassWithUnobserved, "PASS needs every rubric criterion observed and met")
		}
	case "CHANGES_REQUESTED":
		for _, c := range r.Criteria {
			if c.Status == "unobserved" {
				return newErr(CodeUnobservedOutcome, "an unobserved criterion forces UNOBSERVABLE or NEEDS_HUMAN")
			}
		}
	}
	if _, err := checkStrValue(r.RequestID, "request_id", requestIDRE, false); err != nil {
		return err
	}
	if _, err := checkStrValue(r.Nonce, "nonce", nil, false); err != nil {
		return err
	}
	for name, v := range map[string]string{
		"reviewer_actor": r.ReviewerActor, "reviewer_execution_id": r.ReviewerExecutionID,
		"attempt_id": r.AttemptID, "lineage_root": r.LineageRoot,
	} {
		if _, err := checkStrValue(v, name, nil, true); err != nil {
			return err
		}
	}
	if r.EvidenceRef != "" {
		if _, err := checkStrValue(r.EvidenceRef, "evidence_ref", evidenceIDRE, false); err != nil {
			return err
		}
	}
	if r.FindingsRef.ContentHash != "" {
		if _, err := checkStrValue(r.FindingsRef.ContentHash, "findings_ref.content_hash", digestRE, false); err != nil {
			return err
		}
	}
	if _, err := checkStrValue(r.CreatedAt, "created_at", createdAtRE, true); err != nil {
		return err
	}
	return nil
}

func artifactRefFromValue(v any) (ArtifactRef, error) {
	m, err := asMap(v, "findings_ref")
	if err != nil {
		return ArtifactRef{}, err
	}
	if err := checkKeys(m, keySet("name", "kind", "content_hash"), "findings_ref"); err != nil {
		return ArtifactRef{}, newErr(CodeMalformed, "findings_ref: "+err.Error())
	}
	var out ArtifactRef
	for name, dst := range map[string]*string{"name": &out.Name, "kind": &out.Kind, "content_hash": &out.ContentHash} {
		s, ok := getOr(m, name).(string)
		if !ok {
			return ArtifactRef{}, newErr(CodeMalformed, "findings_ref: "+name+" must be a string")
		}
		*dst = s
	}
	return out, nil
}

// ParseReceipt strictly decodes a receipt and, when it carries a
// content_hash or receipt_id, recomputes and verifies them.
func ParseReceipt(data []byte) (ReviewReceipt, error) {
	m, err := decodeObject(data, "receipt")
	if err != nil {
		return ReviewReceipt{}, err
	}
	return receiptFromMap(m)
}

func receiptFromMap(m map[string]any) (ReviewReceipt, error) {
	if err := checkKeys(m, receiptKeys, "receipt"); err != nil {
		return ReviewReceipt{}, err
	}
	if err := checkAPI(m, ReceiptKind); err != nil {
		return ReviewReceipt{}, err
	}
	raw, ok := m["criteria"].([]any)
	if !ok {
		return ReviewReceipt{}, newErr(CodeMalformed, "criteria must be a list")
	}
	criteria := make([]Criterion, 0, len(raw))
	for _, item := range raw {
		im, err := asMap(item, "criterion")
		if err != nil {
			return ReviewReceipt{}, err
		}
		if err := checkKeys(im, keySet("id", "status"), "criterion"); err != nil {
			return ReviewReceipt{}, err
		}
		id, err := checkStr(im["id"], "criterion.id", nil, false)
		if err != nil {
			return ReviewReceipt{}, err
		}
		st, err := checkStr(im["status"], "criterion.status", nil, false)
		if err != nil {
			return ReviewReceipt{}, err
		}
		criteria = append(criteria, Criterion{ID: id, Status: st})
	}
	fv, present := m["findings_ref"]
	if !present {
		fv = map[string]any{}
	}
	findings, err := artifactRefFromValue(fv)
	if err != nil {
		return ReviewReceipt{}, err
	}
	r := ReviewReceipt{Criteria: criteria, FindingsRef: findings}
	if r.RequestID, err = checkStr(m["request_id"], "request_id", nil, false); err != nil {
		return ReviewReceipt{}, err
	}
	if r.Subject, err = subjectFromValue(m["subject"]); err != nil {
		return ReviewReceipt{}, err
	}
	if r.Rubric, err = checkChoice(m["rubric"], rubricNames, "rubric"); err != nil {
		return ReviewReceipt{}, err
	}
	if r.Outcome, err = checkStr(m["outcome"], "outcome", nil, false); err != nil {
		return ReviewReceipt{}, err
	}
	if r.Mode, err = checkStr(m["mode"], "mode", nil, false); err != nil {
		return ReviewReceipt{}, err
	}
	if r.Nonce, err = checkStr(m["nonce"], "nonce", nil, false); err != nil {
		return ReviewReceipt{}, err
	}
	if r.Assurance, err = checkStr(m["assurance"], "assurance", nil, false); err != nil {
		return ReviewReceipt{}, err
	}
	for name, dst := range map[string]*string{
		"reviewer_actor": &r.ReviewerActor, "reviewer_execution_id": &r.ReviewerExecutionID,
		"attempt_id": &r.AttemptID, "lineage_root": &r.LineageRoot, "evidence_ref": &r.EvidenceRef,
	} {
		if *dst, err = checkStr(getOr(m, name), name, nil, true); err != nil {
			return ReviewReceipt{}, err
		}
	}
	if r.CreatedAt, err = createdAt(m); err != nil {
		return ReviewReceipt{}, err
	}
	if r.ContentHash, err = checkStr(getOr(m, "content_hash"), "content_hash", nil, true); err != nil {
		return ReviewReceipt{}, err
	}
	if r.ReceiptID, err = checkStr(getOr(m, "receipt_id"), "receipt_id", nil, true); err != nil {
		return ReviewReceipt{}, err
	}
	if err := r.Validate(); err != nil {
		return ReviewReceipt{}, err
	}
	if r.ContentHash != "" || r.ReceiptID != "" {
		if err := checkIdentity(r.ContentHash, r.ReceiptID, sealHash(r.payload()), ReceiptIDPrefix); err != nil {
			return ReviewReceipt{}, err
		}
	}
	return r, nil
}
