package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
)

func TestJWKSAndMetadata(t *testing.T) {
	o := auth.NewOAuthServer("https://api.example.test", "", "", []byte("s"), nil, nil)
	h := &Handlers{opts: Options{OAuthServer: o}}

	get := func(fn http.HandlerFunc) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		fn(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		return rec
	}
	if rec := get(h.handleJWKS); rec.Code != http.StatusNotFound {
		t.Fatalf("jwks without keys = %d, want 404", rec.Code)
	}
	if body := get(h.handleOAuthMeta).Body.String(); strings.Contains(body, "jwks_uri") {
		t.Fatal("jwks_uri advertised without keys")
	}

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(priv)
	keys, _ := json.Marshal(map[string]any{"active": "k1", "keys": []map[string]string{{
		"kid": "k1", "alg": "EdDSA",
		"private_key_pem": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
	}}})
	if err := o.ConfigureSigning(auth.JWTSigningConfig{Alg: "EdDSA", KeysJSON: string(keys), AcceptHS256: true}); err != nil {
		t.Fatal(err)
	}
	rec := get(h.handleJWKS)
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/jwk-set+json" {
		t.Fatalf("jwks = %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	var doc struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil || len(doc.Keys) != 1 {
		t.Fatalf("jwks body: %v %s", err, rec.Body)
	}
	k := doc.Keys[0]
	if k["kid"] != "k1" || k["alg"] != "EdDSA" || k["use"] != "sig" || k["d"] != nil {
		t.Fatalf("jwk = %v", k)
	}
	if body := get(h.handleOAuthMeta).Body.String(); !strings.Contains(body, `"jwks_uri":"https://api.example.test/.well-known/jwks.json"`) {
		t.Fatalf("jwks_uri missing: %s", body)
	}
}
