package auth

import (
	"context"
	"strings"
	"testing"
)

func TestAccessTokenClientIDClaim(t *testing.T) {
	o := newResourceServer(t)
	const cid = "https://claude.ai/oauth/client.json"
	tok, err := o.issueJWTFor("alice", "", nil, "", cid)
	if err != nil {
		t.Fatal(err)
	}
	u, err := o.ValidateJWT(tok)
	if err != nil || u.OAuthClientID() != cid {
		t.Fatalf("OAuthClientID = %q, %v", u.OAuthClientID(), err)
	}
	v, err := newLocalOAuthProvider(o).Verify(context.Background(), tok)
	if err != nil {
		t.Fatal(err)
	}
	if got := userFromVerified(v).OAuthClientID(); got != cid {
		t.Fatalf("registry path OAuthClientID = %q", got)
	}

	for name, id := range map[string]string{"empty": "", "too long": strings.Repeat("a", 513), "control": "a\nb"} {
		tok, err := o.issueJWTFor("alice", "", nil, "", id)
		if err != nil {
			t.Fatal(err)
		}
		u, err := o.ValidateJWT(tok)
		if err != nil || u.OAuthClientID() != "" {
			t.Fatalf("%s: OAuthClientID = %q, %v", name, u.OAuthClientID(), err)
		}
	}
	tok, _ = o.IssueJWT("alice", "", nil)
	if u, err := o.ValidateJWT(tok); err != nil || u.OAuthClientID() != "" {
		t.Fatalf("IssueJWT client id = %q, %v", u.OAuthClientID(), err)
	}
}
