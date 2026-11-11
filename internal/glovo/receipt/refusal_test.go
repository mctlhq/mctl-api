package receipt

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/mctlhq/mctl-api/internal/bridge"
	"github.com/mctlhq/mctl-api/internal/glovo"
)

// T22: how a collaborator failure maps to the section 10 code.
func TestRefusalOf(t *testing.T) {
	for name, c := range map[string]struct {
		in   error
		want glovo.Code
	}{
		"typed refusal keeps its code": {glovo.Refuse(glovo.CodeApprovalExpired), glovo.CodeApprovalExpired},
		"wrapped typed refusal":        {fmt.Errorf("x: %w", glovo.Refuse(glovo.CodeApprovalReplayed)), glovo.CodeApprovalReplayed},
		"lock timeout":                 {&pgconn.PgError{Code: "55P03"}, glovo.CodeTenantBusy},
		"io failure":                   {errors.New("connection reset"), glovo.CodeUnavailable},
		"deadlock is not a success":    {&pgconn.PgError{Code: "40P01"}, glovo.CodeUnavailable},
		"existing refusal untouched":   {refuse(glovo.CodeNoTenant), glovo.CodeNoTenant},
	} {
		t.Run(name, func(t *testing.T) {
			err := refusalOf(c.in)
			got, ok := CodeOf(err)
			if !ok || got != c.want {
				t.Fatalf("code = %q, want %q", got, c.want)
			}
			if !errors.Is(err, bridge.ErrWriteFenceRefused) || !errors.Is(err, glovo.Refuse(c.want)) {
				t.Fatalf("%v must match ErrWriteFenceRefused and the glovo code", err)
			}
		})
	}
	if refusalOf(nil) != nil {
		t.Fatal("nil must stay nil")
	}
}

// T17: a refusal says the code and nothing else, whatever the cause carried.
func TestRefusalIsSecretFree(t *testing.T) {
	cause := errors.New("password=hunter2 secret_ref=vault://x prn_OWNER00000000000000000001")
	msg := refusalOf(cause).Error()
	for _, leak := range []string{"hunter2", "vault://", "prn_"} {
		if strings.Contains(msg, leak) {
			t.Fatalf("refusal leaks %q: %s", leak, msg)
		}
	}
	if msg != "write_fence_refused: unavailable" {
		t.Fatalf("message = %q", msg)
	}
}

func TestRefusalIsMatchesAnotherRefusalOfTheSameCode(t *testing.T) {
	a := refuse(glovo.CodeApprovalInvalid)
	if !errors.Is(a, refuse(glovo.CodeApprovalInvalid)) {
		t.Fatal("same-code refusals must match")
	}
	if errors.Is(a, refuse(glovo.CodeUnavailable)) {
		t.Fatal("different-code refusals must not match")
	}
}
