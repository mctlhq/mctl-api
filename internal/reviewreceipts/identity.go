package reviewreceipts

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// canonicalJSON mirrors Python json.dumps(sort_keys=True,
// separators=(",", ":"), ensure_ascii=True) for the value kinds used by
// review documents: map[string]any, []any, []string, string.
func canonicalJSON(v any) []byte {
	var b strings.Builder
	writeCanonical(&b, v)
	return []byte(b.String())
}

func writeCanonical(b *strings.Builder, v any) {
	switch x := v.(type) {
	case string:
		writeString(b, x)
	case []string:
		b.WriteByte('[')
		for i, s := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, s)
		}
		b.WriteByte(']')
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			writeCanonical(b, e)
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, k)
			b.WriteByte(':')
			writeCanonical(b, x[k])
		}
		b.WriteByte('}')
	default:
		panic(fmt.Sprintf("reviewreceipts: unsupported canonical value %T", v))
	}
}

func writeString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\f':
			b.WriteString(`\f`)
		case r >= 0x20 && r <= 0x7e:
			b.WriteRune(r)
		case r >= 0x10000:
			r -= 0x10000
			fmt.Fprintf(b, `\u%04x\u%04x`, 0xd800+(r>>10), 0xdc00+(r&0x3ff))
		default:
			fmt.Fprintf(b, `\u%04x`, r)
		}
	}
	b.WriteByte('"')
}

func sealHash(payload map[string]any) string {
	sum := sha256.Sum256(canonicalJSON(payload))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func idFor(prefix, hash string) string { return prefix + hash[7:23] }

func checkIdentity(contentHash, id, expectedHash, prefix string) error {
	if contentHash != expectedHash || id != idFor(prefix, expectedHash) {
		return newErr(CodeBadIdentity, "content_hash or id does not match the document")
	}
	return nil
}

func toAnySlice(in []Criterion) []any {
	out := make([]any, 0, len(in))
	for _, c := range in {
		out = append(out, map[string]any{"id": c.ID, "status": c.Status})
	}
	return out
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (r ReviewRequest) payload() map[string]any {
	return map[string]any{
		"api_version":            APIVersion,
		"kind":                   RequestKind,
		"subject":                r.Subject.Dict(),
		"rubric":                 r.Rubric,
		"mode":                   r.Mode,
		"author_actors":          nonNil(r.AuthorActors),
		"authoring_execution_id": r.AuthoringExecutionID,
		"authoring_attempt_ids":  nonNil(r.AuthoringAttemptIDs),
		"authoring_lineage_root": r.AuthoringLineageRoot,
		"nonce":                  r.Nonce,
	}
}

// Dict mirrors Tier A ReviewRequest.to_dict().
func (r ReviewRequest) Dict() map[string]any {
	d := r.payload()
	d["request_id"] = r.RequestID
	d["content_hash"] = r.ContentHash
	d["created_at"] = r.CreatedAt
	return d
}

func (c ArtifactRef) dict() map[string]any {
	return map[string]any{"name": c.Name, "kind": c.Kind, "content_hash": c.ContentHash}
}

func (r ReviewReceipt) payload() map[string]any {
	return map[string]any{
		"api_version":           APIVersion,
		"kind":                  ReceiptKind,
		"request_id":            r.RequestID,
		"subject":               r.Subject.Dict(),
		"rubric":                r.Rubric,
		"outcome":               r.Outcome,
		"criteria":              toAnySlice(r.Criteria),
		"findings_ref":          r.FindingsRef.dict(),
		"mode":                  r.Mode,
		"assurance":             r.Assurance,
		"reviewer_actor":        r.ReviewerActor,
		"reviewer_execution_id": r.ReviewerExecutionID,
		"attempt_id":            r.AttemptID,
		"lineage_root":          r.LineageRoot,
		"nonce":                 r.Nonce,
		"evidence_ref":          r.EvidenceRef,
	}
}

// Dict mirrors Tier A ReviewReceipt.to_dict().
func (r ReviewReceipt) Dict() map[string]any {
	d := r.payload()
	d["receipt_id"] = r.ReceiptID
	d["content_hash"] = r.ContentHash
	d["created_at"] = r.CreatedAt
	return d
}

// SealRequestInput holds the caller-supplied fields of a request. The nonce
// is an input and is never generated here.
type SealRequestInput struct {
	Subject              ReviewSubject
	Mode                 string
	AuthorActors         []string
	Nonce                string
	AuthoringExecutionID string
	AuthoringAttemptIDs  []string
	AuthoringLineageRoot string
	CreatedAt            string
}

func sortedSet(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// SealRequest is the only constructor that fills ContentHash and RequestID.
func SealRequest(in SealRequestInput) (ReviewRequest, error) {
	if err := in.Subject.Validate(); err != nil {
		return ReviewRequest{}, err
	}
	draft := ReviewRequest{
		Subject:              in.Subject,
		Rubric:               rubricForSubject[in.Subject.Kind],
		Mode:                 in.Mode,
		AuthorActors:         sortedSet(in.AuthorActors),
		Nonce:                in.Nonce,
		AuthoringExecutionID: in.AuthoringExecutionID,
		AuthoringAttemptIDs:  sortedSet(in.AuthoringAttemptIDs),
		AuthoringLineageRoot: in.AuthoringLineageRoot,
		CreatedAt:            in.CreatedAt,
	}
	if err := draft.Validate(); err != nil {
		return ReviewRequest{}, err
	}
	draft.ContentHash = sealHash(draft.payload())
	draft.RequestID = idFor(RequestIDPrefix, draft.ContentHash)
	return draft, nil
}

// SealReceiptInput holds the caller-supplied fields of a receipt. The
// receipt takes the request's subject, rubric, mode and nonce.
type SealReceiptInput struct {
	Outcome             string
	Criteria            []Criterion
	FindingsRef         ArtifactRef
	ReviewerActor       string
	ReviewerExecutionID string
	AttemptID           string
	LineageRoot         string
	EvidenceRef         string
	CreatedAt           string
}

// SealReceipt is the only constructor that fills a receipt's identity. A
// manual request forces assurance=advisory.
func SealReceipt(request ReviewRequest, in SealReceiptInput) (ReviewReceipt, error) {
	assurance := AssuranceIndependent
	if request.Mode == ModeManual {
		assurance = AssuranceAdvisory
	}
	draft := ReviewReceipt{
		RequestID:           request.RequestID,
		Subject:             request.Subject,
		Rubric:              request.Rubric,
		Outcome:             in.Outcome,
		Criteria:            append([]Criterion(nil), in.Criteria...),
		Mode:                request.Mode,
		Nonce:               request.Nonce,
		FindingsRef:         in.FindingsRef,
		Assurance:           assurance,
		ReviewerActor:       in.ReviewerActor,
		ReviewerExecutionID: in.ReviewerExecutionID,
		AttemptID:           in.AttemptID,
		LineageRoot:         in.LineageRoot,
		EvidenceRef:         in.EvidenceRef,
		CreatedAt:           in.CreatedAt,
	}
	if err := draft.Validate(); err != nil {
		return ReviewReceipt{}, err
	}
	draft.ContentHash = sealHash(draft.payload())
	draft.ReceiptID = idFor(ReceiptIDPrefix, draft.ContentHash)
	return draft, nil
}
