package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/mctlhq/mctl-api/internal/customerdelete"
	"github.com/mctlhq/mctl-api/internal/principals"
)

var errSignupInvalidResponse = errors.New("invalid invitation response")

type signupProviderError struct {
	stage  string
	status int
	cause  error
}

func (e *signupProviderError) Error() string { return "GitHub identity lookup unavailable" }
func (e *signupProviderError) Unwrap() error { return e.cause }

// Provider/driver errors can contain credentials, URLs or applicant data.
// Preserve actionable stage, status, SQLSTATE and class without their raw text.
type signupDiagnostic struct{ cause error }

func (e signupDiagnostic) LogValue() slog.Value {
	kind := "operation_failed"
	switch {
	case errors.Is(e.cause, context.Canceled):
		kind = "cancelled"
	case errors.Is(e.cause, context.DeadlineExceeded):
		kind = "deadline_exceeded"
	case errors.Is(e.cause, errSignupInvalidResponse):
		kind = "invalid_response"
	case errors.Is(e.cause, principals.ErrSignupConflict):
		kind = "immutable_record_conflict"
	case errors.Is(e.cause, principals.ErrSignupLeaseLost):
		kind = "lease_lost"
	}
	attrs := []slog.Attr{slog.String("kind", kind), slog.String("type", fmt.Sprintf("%T", e.cause))}
	var database *pgconn.PgError
	if errors.As(e.cause, &database) {
		attrs = append(attrs, slog.String("sqlstate", database.Code))
	}
	var bridge *customerdelete.SignupSiteError
	if errors.As(e.cause, &bridge) {
		attrs = append(attrs, slog.String("provider", "site_bridge"), slog.String("stage", bridge.Stage))
		if bridge.Status > 0 {
			attrs = append(attrs, slog.Int("http_status", bridge.Status))
		}
	}
	var github *signupProviderError
	if errors.As(e.cause, &github) {
		attrs = append(attrs, slog.String("provider", "github"), slog.String("stage", github.stage))
		if github.status > 0 {
			attrs = append(attrs, slog.Int("http_status", github.status))
		}
	}
	var syntax *json.SyntaxError
	var invalidType *json.UnmarshalTypeError
	if errors.As(e.cause, &syntax) || errors.As(e.cause, &invalidType) {
		attrs = append(attrs, slog.String("response_error", "invalid_json"))
	}
	var transport *url.Error
	if errors.As(e.cause, &transport) {
		attrs = append(attrs, slog.String("transport_error", "request_failed"))
	}
	return slog.GroupValue(attrs...)
}
func signupFailure(ctx context.Context, operation string, err error, attrs ...any) {
	fields := append([]any{"operation", operation, "error", signupDiagnostic{cause: err}}, attrs...)
	if errors.Is(err, principals.ErrSignupLeaseLost) || errors.Is(err, context.Canceled) {
		slog.DebugContext(ctx, "signup operation interrupted", fields...)
		return
	}
	slog.WarnContext(ctx, "signup operation failed", fields...)
}
