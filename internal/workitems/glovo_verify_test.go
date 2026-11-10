package workitems

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/mctlhq/mctl-api/internal/glovo"
)

func reasonOf(err error) string {
	var nr *glovo.NotReadyError
	if errors.As(err, &nr) {
		return nr.Reason
	}
	return fmt.Sprint(err)
}

// T15e/T18: the start-up proof passes on a converged database and turns red,
// with the named reason, for each deliberate mutation.
func TestVerifyGlovoApprovalSchema(t *testing.T) {
	ctx := context.Background()
	if err := VerifyGlovoApprovalSchema(ctx, newGlovoEnv(t).rtp); err != nil {
		t.Fatalf("converged database: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(e *glovoEnv) []string
		reason string
	}{
		{"version row removed", func(*glovoEnv) []string { return []string{`DELETE FROM glovo.approval_schema_version`} }, NotReadyApprovalVersion},
		{"version row wrong", func(*glovoEnv) []string {
			return []string{`UPDATE glovo.approval_schema_version SET version = version + 1`}
		}, NotReadyApprovalVersion},
		{"guard trigger disabled", func(*glovoEnv) []string {
			return []string{`ALTER TABLE public.action_approval_requests DISABLE TRIGGER aar_guard`}
		}, NotReadyApprovalTrigger},
		{"binding guard disabled", func(*glovoEnv) []string {
			return []string{`ALTER TABLE glovo.approval_bindings DISABLE TRIGGER approval_bindings_guard`}
		}, NotReadyApprovalTrigger},
		{"binding-required trigger disabled", func(*glovoEnv) []string {
			return []string{`ALTER TABLE public.action_approval_requests DISABLE TRIGGER aar_binding_required`}
		}, NotReadyApprovalTrigger},
		{"runtime role is a member of the owner", func(e *glovoEnv) []string {
			return []string{fmt.Sprintf(`GRANT %s TO %s`, e.mig, e.rt)}
		}, NotReadyApprovalOwner},
		{"table-wide UPDATE granted", func(e *glovoEnv) []string {
			return []string{fmt.Sprintf(`GRANT UPDATE ON public.action_approval_requests TO %s`, e.rt)}
		}, NotReadyApprovalGrants},
		{"DELETE granted", func(e *glovoEnv) []string {
			return []string{fmt.Sprintf(`GRANT DELETE ON glovo.approval_bindings TO %s`, e.rt)}
		}, NotReadyApprovalGrants},
		{"SELECT revoked", func(e *glovoEnv) []string {
			return []string{fmt.Sprintf(`REVOKE SELECT ON public.action_approval_requests FROM %s`, e.rt)}
		}, NotReadyApprovalGrants},
		{"extra update column", func(e *glovoEnv) []string {
			return []string{fmt.Sprintf(`GRANT UPDATE (tenant) ON glovo.approval_bindings TO %s`, e.rt)}
		}, NotReadyApprovalGrants},
		{"work item write revoked", func(e *glovoEnv) []string {
			return []string{fmt.Sprintf(`REVOKE INSERT ON public.work_items FROM %s`, e.rt)}
		}, NotReadyApprovalGrants},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newGlovoEnv(t)
			mp := e.pool(e.migURL)
			for _, q := range c.mutate(e) {
				var exec func(context.Context, string, ...any) (pgconn.CommandTag, error) = mp.Exec
				if strings.HasPrefix(q, "GRANT "+e.mig) { // role membership is a cluster-level grant
					root := e.conn(e.base)
					exec = root.Exec
				}
				if _, err := exec(ctx, q); err != nil {
					t.Fatalf("mutation %q: %v", q, err)
				}
			}
			err := VerifyGlovoApprovalSchema(ctx, e.rtp)
			if got := reasonOf(err); got != c.reason {
				t.Fatalf("reason = %q (%v), want %q", got, err, c.reason)
			}
		})
	}
}

// A read that cannot run is not_ready, never a pass.
func TestVerifyGlovoApprovalSchemaUnreadableIsNotReady(t *testing.T) {
	e := newGlovoEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := VerifyGlovoApprovalSchema(ctx, e.rtp)
	if got := reasonOf(err); got != NotReadyApprovalCheckSQL {
		t.Fatalf("reason = %q, want %q", got, NotReadyApprovalCheckSQL)
	}
}
