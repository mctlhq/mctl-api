package api

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/url"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/mctlhq/mctl-api/internal/customerdelete"
	"github.com/mctlhq/mctl-api/internal/principals"
)

func TestSignupDiagnosticsPreserveCausesWithoutCredentialOrContactText(t *testing.T) {
	secret := "fixture-private-token-and-email@example.com"
	cases := []struct {
		err  error
		want string
	}{
		{principals.ErrSignupConflict, "immutable_record_conflict"},
		{principals.ErrSignupLeaseLost, "lease_lost"},
		{&pgconn.PgError{Code: "08006", Message: secret}, "08006"},
		{&customerdelete.SignupSiteError{Stage: "service_authentication", Status: 401, Cause: errors.New(secret)}, "service_authentication"},
		{&url.Error{Op: "Get", URL: "https://example.com/bot" + secret, Err: errors.New(secret)}, "request_failed"},
		{context.DeadlineExceeded, "deadline_exceeded"},
	}
	for _, tc := range cases {
		var buffer bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&buffer, nil))
		logger.Warn("probe", "error", signupDiagnostic{cause: tc.err})
		result := buffer.String()
		if strings.Contains(result, secret) {
			t.Fatal("private error text escaped the diagnostic wrapper")
		}
		if !strings.Contains(result, tc.want) {
			t.Fatalf("missing safe diagnostic %q: %s", tc.want, result)
		}
	}
}
