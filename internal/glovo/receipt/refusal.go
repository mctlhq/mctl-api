package receipt

import (
	"errors"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/mctlhq/mctl-api/internal/bridge"
	"github.com/mctlhq/mctl-api/internal/glovo"
)

// Refusal is a fence refusal with its design section 10 code. It wraps
// bridge.ErrWriteFenceRefused, so the permit transaction rolls back and the
// bridge maps it as it maps any fence refusal.
type Refusal struct{ Code glovo.Code }

func (r *Refusal) Error() string { return "write_fence_refused: " + string(r.Code) }

func (r *Refusal) Unwrap() error { return bridge.ErrWriteFenceRefused }

// Is matches a *glovo.Error or another *Refusal of the same code, so errors.Is(err,
// glovo.Refuse(code)) works on a fence refusal.
func (r *Refusal) Is(target error) bool {
	switch t := target.(type) {
	case *glovo.Error:
		return t != nil && t.Code == r.Code
	case *Refusal:
		return t != nil && t.Code == r.Code
	}
	return false
}

// CodeOf is the section 10 code of a fence refusal.
func CodeOf(err error) (glovo.Code, bool) {
	var r *Refusal
	if errors.As(err, &r) {
		return r.Code, true
	}
	return "", false
}

func refuse(c glovo.Code) error { return &Refusal{Code: c} }

// refusalOf turns an error of a collaborator into a refusal: a typed Glovo
// refusal keeps its code, a lock timeout is tenant_busy, anything else (an
// I/O failure) is the retryable unavailable. It never lets an unclassified
// failure read as success.
func refusalOf(err error) error {
	if err == nil {
		return nil
	}
	var r *Refusal
	if errors.As(err, &r) {
		return err
	}
	var ge *glovo.Error
	if errors.As(err, &ge) {
		return refuse(ge.Code)
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "55P03" {
		return refuse(glovo.CodeTenantBusy)
	}
	return refuse(glovo.CodeUnavailable)
}
