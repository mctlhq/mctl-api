package reviewreceipts

// Typed refusal codes. These are exactly the Tier A document-level codes
// (mctl-agents orchestrator/review_receipts.py); no other code exists here.
const (
	CodeMalformed          = "review_malformed"
	CodeUnknownKey         = "review_unknown_key"
	CodeBadSubject         = "review_bad_subject"
	CodeBadIdentity        = "review_bad_identity"
	CodeRubricMismatch     = "review_rubric_mismatch"
	CodePassWithUnobserved = "review_pass_with_unobserved"
	CodeUnobservedOutcome  = "review_unobserved_outcome"
)

// Error is a fail-closed validation failure carrying a stable Code.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// Is lets errors.Is(err, ErrX) match on the code alone.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Message == "" && t.Code == e.Code
}

// Sentinels, one per code. Use with errors.Is.
var (
	ErrMalformed          = &Error{Code: CodeMalformed}
	ErrUnknownKey         = &Error{Code: CodeUnknownKey}
	ErrBadSubject         = &Error{Code: CodeBadSubject}
	ErrBadIdentity        = &Error{Code: CodeBadIdentity}
	ErrRubricMismatch     = &Error{Code: CodeRubricMismatch}
	ErrPassWithUnobserved = &Error{Code: CodePassWithUnobserved}
	ErrUnobservedOutcome  = &Error{Code: CodeUnobservedOutcome}
)

func newErr(code, msg string) *Error { return &Error{Code: code, Message: msg} }
