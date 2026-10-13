package api

// GET /api/v1/identity/self (mctl-api#376 D3): who the API resolved the
// caller to, in the identity/v1 shape the policy checkpoint and the
// evidence envelope read. Read-only, and everything in it is derived from
// authentication and the delegation gate; nothing is taken from the
// request.

import (
	"context"
	"net/http"

	"github.com/mctlhq/mctl-api/internal/auth"
)

// IdentitySelfSchemaVersion is the schema_version of GET /identity/self.
const IdentitySelfSchemaVersion = "identity/v1"

// identityParty is one side of a request: the actor that authenticated, or
// the subject it acts for.
type identityParty struct {
	PrincipalID string `json:"principal_id"`
	Kind        string `json:"kind"`
	Name        string `json:"name"`
}

// identityGrant is the delegation grant a request runs under.
type identityGrant struct {
	Kind string `json:"kind"`
	Ref  string `json:"ref"`
}

type identitySelf struct {
	SchemaVersion string         `json:"schema_version"`
	Actor         identityParty  `json:"actor"`
	Subject       *identityParty `json:"subject"`
	ExecutionID   string         `json:"execution_id"`
	WorkItemID    string         `json:"work_item_id"`
	AgentRunID    string         `json:"agent_run_id"`
	Grant         *identityGrant `json:"grant"`
}

type delegationGrantKey struct{}

// withDelegationGrant records the grant agentPrincipalGate resolved, so a
// handler can report it without re-resolving the header.
func withDelegationGrant(ctx context.Context, g identityGrant) context.Context {
	return context.WithValue(ctx, delegationGrantKey{}, g)
}

func delegationGrantFrom(ctx context.Context) *identityGrant {
	if g, ok := ctx.Value(delegationGrantKey{}).(identityGrant); ok {
		return &g
	}
	return nil
}

// actorAndSubject splits the authenticated caller into the actor that
// authenticated and the subject it acts for. The subject is nil -- never a
// copy of the actor -- unless the request is delegated (an agent run under
// a grant) or relayed (a surface for a linked human): a policy rule needs
// "acting for itself" and "acting for a human" to be distinguishable.
//
// It reads only what the auth middleware and the gates attached to u.
// Nothing here parses a principal string to decide a kind.
func actorAndSubject(u *auth.User) (identityParty, *identityParty) {
	// Both on-behalf-of constructors build a human subject: NewDelegatedUser
	// and NewRelayedUser. The actor is the principal that carried it.
	if agent, delegated := u.DelegatingAgent(); delegated {
		return identityParty{PrincipalID: u.ViaPrincipalID(), Kind: auth.KindAgent, Name: agent},
			&identityParty{PrincipalID: u.PrincipalID(), Kind: auth.KindHuman, Name: u.ID}
	}
	if _, relayed := u.RelaySurface(); relayed {
		return identityParty{PrincipalID: u.ViaPrincipalID(), Kind: auth.KindService, Name: u.ActingPrincipal()},
			&identityParty{PrincipalID: u.PrincipalID(), Kind: auth.KindHuman, Name: u.ID}
	}
	actor := identityParty{PrincipalID: u.PrincipalID(), Name: u.ID}
	if id, ok := u.Identity(); ok {
		actor.Kind = id.Kind
	}
	if name, isAgent := u.AgentName(); isAgent {
		actor.Name = name
	}
	return actor, nil
}

// GetIdentitySelf handles GET /api/v1/identity/self.
func (h *Handlers) GetIdentitySelf(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	actor, subject := actorAndSubject(user)
	writeJSON(w, http.StatusOK, identitySelf{
		SchemaVersion: IdentitySelfSchemaVersion,
		Actor:         actor,
		Subject:       subject,
		ExecutionID:   user.ExecutionID(),
		WorkItemID:    user.WorkItemID(),
		AgentRunID:    user.AgentRunID(),
		Grant:         delegationGrantFrom(r.Context()),
	})
}
