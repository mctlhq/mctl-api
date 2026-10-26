package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

const testBase = "https://api.example.test"

func pemPriv(t *testing.T, k any) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func pemPub(t *testing.T, k any) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func genKeys(t *testing.T) (edPub ed25519.PublicKey, edPriv ed25519.PrivateKey, ec *ecdsa.PrivateKey) {
	t.Helper()
	edPub, edPriv, _ = ed25519.GenerateKey(rand.Reader)
	ec, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return
}

func keysJSON(t *testing.T, doc signingKeysDoc) string {
	t.Helper()
	b, _ := json.Marshal(doc)
	return string(b)
}

func newSigner(t *testing.T, alg, keys string) *OAuthServer {
	t.Helper()
	o := NewOAuthServer(testBase, "", "", []byte("secret"), nil, nil)
	if err := o.ConfigureSigning(JWTSigningConfig{Alg: alg, KeysJSON: keys, AcceptHS256: true}); err != nil {
		t.Fatal(err)
	}
	return o
}

func counter(alg, result string) float64 {
	return testutil.ToFloat64(oauthJWTVerifications.WithLabelValues(alg, result))
}

func TestAudienceEnforcement(t *testing.T) {
	o := NewOAuthServer(testBase, "", "", []byte("secret"), nil, nil)
	exp := time.Now().Add(time.Hour).Unix()
	mk := func(a audience) string {
		tok, err := signJWT(jwtPayload{Issuer: testBase, Subject: "alice", Audience: a, ExpiresAt: exp}, o.JWTSecret)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	// T1: foreign aud refused through ValidateJWT and the federation provider.
	before := counter("HS256", "aud_mismatch")
	foreign := mk(audience{"https://mcp.mctl.ai"})
	if _, err := o.ValidateJWT(foreign); err == nil {
		t.Fatal("foreign aud accepted by ValidateJWT")
	}
	if _, err := newLocalOAuthProvider(o).Verify(context.Background(), foreign); err == nil {
		t.Fatal("foreign aud accepted by localOAuthProvider")
	}
	if got := counter("HS256", "aud_mismatch") - before; got != 2 {
		t.Fatalf("aud_mismatch delta = %v, want 2", got)
	}
	// T2: arrays.
	if _, err := o.ValidateJWT(mk(audience{"x", testBase + "/"})); err != nil {
		t.Fatalf("array containing the API aud refused: %v", err)
	}
	if _, err := o.ValidateJWT(mk(audience{"x", "y"})); err == nil {
		t.Fatal("array without the API aud accepted")
	}
	// T3: aud-less grace.
	b := testutil.ToFloat64(oauthJWTAudlessAccepted)
	if _, err := o.ValidateJWT(mk(nil)); err != nil {
		t.Fatalf("aud-less HS256 refused during grace: %v", err)
	}
	if testutil.ToFloat64(oauthJWTAudlessAccepted)-b != 1 {
		t.Fatal("aud-less counter did not increment")
	}
	o.RequireAud = true
	if _, err := o.ValidateJWT(mk(nil)); err == nil {
		t.Fatal("aud-less HS256 accepted with RequireAud")
	}
}

func TestMintedTokenCarriesAudience(t *testing.T) {
	o := NewOAuthServer(testBase, "", "", []byte("secret"), nil, nil)
	tok, err := o.IssueJWT("alice", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	p, err := verifyJWT(tok, o.JWTSecret, testBase)
	if err != nil || !p.Audience.contains(testBase) {
		t.Fatalf("aud = %v, err = %v", p, err)
	}
}

func TestAlgPinning(t *testing.T) {
	o := NewOAuthServer(testBase, "", "", []byte("secret"), nil, nil)
	hmacCalls := 0
	o.onHMAC = func() { hmacCalls++ }
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"` + testBase + `","sub":"a","aud":"` + testBase + `","exp":` + "99999999999" + `}`))
	for _, alg := range []string{"none", "HS512", "RS256", ""} {
		h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"` + alg + `"}`))
		before := counter(metricAlg(alg), "alg_refused")
		if _, err := o.ValidateJWT(h + "." + payload + "."); err == nil {
			t.Fatalf("alg %q accepted", alg)
		}
		if counter(metricAlg(alg), "alg_refused")-before != 1 {
			t.Fatalf("alg %q: alg_refused not counted", alg)
		}
	}
	if hmacCalls != 0 {
		t.Fatal("HMAC computed for a refused alg")
	}
	// T5: valid HS256 refused when HS256 is not accepted.
	tok, _ := signJWT(jwtPayload{Issuer: testBase, Audience: audience{testBase}, ExpiresAt: 99999999999}, o.JWTSecret)
	o.RejectHS256 = true
	if _, err := o.ValidateJWT(tok); err == nil || hmacCalls != 0 {
		t.Fatalf("HS256 accepted with RejectHS256 (err=%v, hmac=%d)", err, hmacCalls)
	}
}

func TestAlgorithmConfusion(t *testing.T) {
	edPub, edPriv, _ := genKeys(t)
	o := newSigner(t, JWTAlgEdDSA, keysJSON(t, signingKeysDoc{Active: "k1", Keys: []signingKeyEntry{
		{Kid: "k1", Alg: JWTAlgEdDSA, PrivateKeyPEM: pemPriv(t, edPriv)}}}))
	// HS256 token keyed with the public key bytes.
	tok, _ := signJWT(jwtPayload{Issuer: testBase, Audience: audience{testBase}, ExpiresAt: 99999999999}, []byte(edPub))
	if _, err := o.ValidateJWT(tok); err == nil {
		t.Fatal("HS256 token keyed with the public key accepted")
	}
}

func TestAsymmetricRoundTrip(t *testing.T) {
	_, edPriv, ec := genKeys(t)
	for _, tc := range []struct{ alg, pem string }{
		{JWTAlgEdDSA, pemPriv(t, edPriv)},
		{JWTAlgES256, pemPriv(t, ec)},
	} {
		o := newSigner(t, tc.alg, keysJSON(t, signingKeysDoc{Active: "k1", Keys: []signingKeyEntry{
			{Kid: "k1", Alg: tc.alg, PrivateKeyPEM: tc.pem}}}))
		tok, err := o.IssueJWT("alice", "", []string{"g"})
		if err != nil {
			t.Fatal(err)
		}
		hdr, _ := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[0])
		var h jwtHeader
		_ = json.Unmarshal(hdr, &h)
		if h.Alg != tc.alg || h.Kid != "k1" {
			t.Fatalf("%s: header = %+v", tc.alg, h)
		}
		if _, err := o.verifyAccessToken(tok); err != nil {
			t.Fatalf("%s: round trip: %v", tc.alg, err)
		}
		// Tampered payload.
		parts := strings.Split(tok, ".")
		parts[1] = base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"` + testBase + `","sub":"root","aud":"` + testBase + `","exp":99999999999}`))
		before := counter(tc.alg, "bad_signature")
		if _, err := o.verifyAccessToken(strings.Join(parts, ".")); err == nil {
			t.Fatalf("%s: tampered token accepted", tc.alg)
		}
		if counter(tc.alg, "bad_signature")-before != 1 {
			t.Fatalf("%s: bad_signature not counted", tc.alg)
		}
		// T11: pre-existing HS256 token with aud still validates.
		hs, _ := signJWT(jwtPayload{Issuer: testBase, Subject: "alice", Audience: audience{testBase}, ExpiresAt: 99999999999}, o.JWTSecret)
		if _, err := o.verifyAccessToken(hs); err != nil {
			t.Fatalf("%s: HS256 drain token refused: %v", tc.alg, err)
		}
	}
}

func TestAsymmetricAudlessRefused(t *testing.T) {
	_, edPriv, _ := genKeys(t)
	o := newSigner(t, JWTAlgEdDSA, keysJSON(t, signingKeysDoc{Active: "k1", Keys: []signingKeyEntry{
		{Kid: "k1", Alg: JWTAlgEdDSA, PrivateKeyPEM: pemPriv(t, edPriv)}}}))
	tok, err := signJWTAsymmetric(jwtPayload{Issuer: testBase, Subject: "a", ExpiresAt: 99999999999}, o.keys.active)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.verifyAccessToken(tok); err == nil {
		t.Fatal("aud-less EdDSA token accepted")
	}
}

func TestKeyRotationAndRetention(t *testing.T) {
	_, oldPriv, _ := genKeys(t)
	_, newPriv, _ := genKeys(t)
	retired := time.Now().Add(-10 * time.Minute)
	doc := keysJSON(t, signingKeysDoc{Active: "new", Keys: []signingKeyEntry{
		{Kid: "new", Alg: JWTAlgEdDSA, PrivateKeyPEM: pemPriv(t, newPriv)},
		{Kid: "old", Alg: JWTAlgEdDSA, PublicKeyPEM: pemPub(t, oldPriv.Public()), RetiredAt: &retired},
	}})
	o := newSigner(t, JWTAlgEdDSA, doc)
	oldKey := &accessTokenKey{kid: "old", alg: JWTAlgEdDSA, private: oldPriv}
	p := jwtPayload{Issuer: testBase, Subject: "a", Audience: audience{testBase}, ExpiresAt: 99999999999}
	tok, _ := signJWTAsymmetric(p, oldKey)
	if _, err := o.verifyAccessToken(tok); err != nil {
		t.Fatalf("retained key refused in window: %v", err)
	}
	if set, _ := o.PublicJWKS(); len(set.Keys) != 2 {
		t.Fatalf("jwks keys = %d, want 2", len(set.Keys))
	}
	// Clock past retention.
	o.keys.now = func() time.Time { return retired.Add(DefaultJWTKeyRetention + time.Second) }
	before := counter("EdDSA", "unknown_kid")
	if _, err := o.verifyAccessToken(tok); err == nil {
		t.Fatal("expired retained key accepted")
	}
	if counter("EdDSA", "unknown_kid")-before != 1 {
		t.Fatal("unknown_kid not counted")
	}
	if set, _ := o.PublicJWKS(); len(set.Keys) != 1 {
		t.Fatalf("jwks keys after expiry = %d, want 1", len(set.Keys))
	}
	// Unknown and missing kid.
	for _, kid := range []string{"nope", ""} {
		tk, _ := signJWTAsymmetric(p, &accessTokenKey{kid: kid, alg: JWTAlgEdDSA, private: oldPriv})
		if _, err := o.verifyAccessToken(tk); err == nil {
			t.Fatalf("kid %q accepted", kid)
		}
	}
}

func TestJWKSIsPublicOnly(t *testing.T) {
	_, edPriv, ec := genKeys(t)
	o := newSigner(t, JWTAlgEdDSA, keysJSON(t, signingKeysDoc{Active: "e", Keys: []signingKeyEntry{
		{Kid: "e", Alg: JWTAlgEdDSA, PrivateKeyPEM: pemPriv(t, edPriv)},
		{Kid: "p", Alg: JWTAlgES256, PrivateKeyPEM: pemPriv(t, ec), RetiredAt: ptrTime(time.Now())},
	}}))
	set, ok := o.PublicJWKS()
	if !ok || len(set.Keys) != 2 {
		t.Fatalf("ok=%v keys=%d", ok, len(set.Keys))
	}
	for _, k := range set.Keys {
		if !k.IsPublic() || k.Use != "sig" || k.KeyID == "" || k.Algorithm == "" {
			t.Fatalf("bad jwk %+v", k)
		}
	}
	b, _ := json.Marshal(set)
	var raw struct {
		Keys []map[string]any `json:"keys"`
	}
	_ = json.Unmarshal(b, &raw)
	for _, k := range raw.Keys {
		for _, m := range []string{"d", "p", "q", "k"} {
			if _, has := k[m]; has {
				t.Fatalf("jwk has private member %q", m)
			}
		}
	}
	if _, ok := NewOAuthServer(testBase, "", "", []byte("s"), nil, nil).PublicJWKS(); ok {
		t.Fatal("JWKS offered without keys")
	}
}

func ptrTime(t time.Time) *time.Time { return &t }

func TestKeySetParserRejections(t *testing.T) {
	edPub, edPriv, ec := genKeys(t)
	priv := pemPriv(t, edPriv)
	now := ptrTime(time.Now())
	many := []signingKeyEntry{}
	for i := 0; i < 9; i++ {
		many = append(many, signingKeyEntry{Kid: string(rune('a' + i)), Alg: JWTAlgEdDSA, PrivateKeyPEM: priv})
	}
	cases := map[string]signingKeysDoc{
		"alg/type mismatch":   {Active: "a", Keys: []signingKeyEntry{{Kid: "a", Alg: JWTAlgES256, PrivateKeyPEM: priv}}},
		"duplicate kid":       {Active: "a", Keys: []signingKeyEntry{{Kid: "a", Alg: JWTAlgEdDSA, PrivateKeyPEM: priv}, {Kid: "a", Alg: JWTAlgEdDSA, PrivateKeyPEM: priv, RetiredAt: now}}},
		"unknown active":      {Active: "zz", Keys: []signingKeyEntry{{Kid: "a", Alg: JWTAlgEdDSA, PrivateKeyPEM: priv, RetiredAt: now}}},
		"active w/o private":  {Active: "a", Keys: []signingKeyEntry{{Kid: "a", Alg: JWTAlgEdDSA, PublicKeyPEM: pemPub(t, edPub)}}},
		"too many":            {Active: "a", Keys: many},
		"private as public":   {Active: "a", Keys: []signingKeyEntry{{Kid: "a", Alg: JWTAlgEdDSA, PrivateKeyPEM: priv}, {Kid: "b", Alg: JWTAlgEdDSA, PublicKeyPEM: priv, RetiredAt: now}}},
		"hmac secret as key":  {Active: "a", Keys: []signingKeyEntry{{Kid: "a", Alg: "HS256", PrivateKeyPEM: "hunter2-secret"}}},
		"P-384 for ES256":     {Active: "a", Keys: []signingKeyEntry{{Kid: "a", Alg: JWTAlgES256, PrivateKeyPEM: pemPriv(t, mustP384(t))}}},
		"retained no retired": {Active: "a", Keys: []signingKeyEntry{{Kid: "a", Alg: JWTAlgEdDSA, PrivateKeyPEM: priv}, {Kid: "b", Alg: JWTAlgEdDSA, PublicKeyPEM: pemPub(t, edPub)}}},
	}
	_ = ec
	for name, doc := range cases {
		_, err := parseAccessTokenKeySet(keysJSON(t, doc), time.Hour, nil)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), "BEGIN") || strings.Contains(err.Error(), "hunter2") {
			t.Errorf("%s: error leaks key material: %v", name, err)
		}
	}
	if _, err := parseAccessTokenKeySet("{not json hunter2", time.Hour, nil); err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Errorf("malformed json: %v", err)
	}
}

func mustP384(t *testing.T) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSigningConfigValidate(t *testing.T) {
	_, edPriv, _ := genKeys(t)
	good := keysJSON(t, signingKeysDoc{Active: "k", Keys: []signingKeyEntry{{Kid: "k", Alg: JWTAlgEdDSA, PrivateKeyPEM: pemPriv(t, edPriv)}}})
	ok := []JWTSigningConfig{
		{AcceptHS256: true},
		{Alg: JWTAlgHS256, AcceptHS256: true},
		{Alg: JWTAlgEdDSA, KeysJSON: good, AcceptHS256: false},
	}
	for i, c := range ok {
		if err := c.Validate(time.Hour); err != nil {
			t.Errorf("ok[%d]: %v", i, err)
		}
	}
	bad := map[string]JWTSigningConfig{
		"eddsa w/o keys":        {Alg: JWTAlgEdDSA, AcceptHS256: true},
		"eddsa blank keys":      {Alg: JWTAlgEdDSA, KeysJSON: "  ", AcceptHS256: true},
		"malformed with hs256":  {KeysJSON: "{oops", AcceptHS256: true},
		"hs256 not accepted":    {Alg: JWTAlgHS256, AcceptHS256: false},
		"unknown alg":           {Alg: "RS256", AcceptHS256: true},
		"retention under ttl":   {Alg: JWTAlgEdDSA, KeysJSON: good, AcceptHS256: true, KeyRetention: time.Minute},
		"active alg != signing": {Alg: JWTAlgES256, KeysJSON: good, AcceptHS256: true},
	}
	for name, c := range bad {
		if err := c.Validate(time.Hour); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRetainedKeyVerifiesAfterRollbackAndRotation(t *testing.T) {
	_, edPriv, ec := genKeys(t)
	edDoc := keysJSON(t, signingKeysDoc{Active: "k1", Keys: []signingKeyEntry{
		{Kid: "k1", Alg: JWTAlgEdDSA, PrivateKeyPEM: pemPriv(t, edPriv)}}})
	tok, err := newSigner(t, JWTAlgEdDSA, edDoc).IssueJWT("alice", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	now := ptrTime(time.Now())
	// Rotation EdDSA -> ES256 with the EdDSA key retained.
	rot := keysJSON(t, signingKeysDoc{Active: "k2", Keys: []signingKeyEntry{
		{Kid: "k2", Alg: JWTAlgES256, PrivateKeyPEM: pemPriv(t, ec)},
		{Kid: "k1", Alg: JWTAlgEdDSA, PrivateKeyPEM: pemPriv(t, edPriv), RetiredAt: now}}})
	if _, err := newSigner(t, JWTAlgES256, rot).verifyAccessToken(tok); err != nil {
		t.Fatalf("rotation: retained EdDSA token refused: %v", err)
	}
	// Rollback to HS256 with only retained keys and no active kid.
	back := keysJSON(t, signingKeysDoc{Keys: []signingKeyEntry{
		{Kid: "k1", Alg: JWTAlgEdDSA, PrivateKeyPEM: pemPriv(t, edPriv), RetiredAt: now}}})
	o := newSigner(t, JWTAlgHS256, back)
	if _, err := o.verifyAccessToken(tok); err != nil {
		t.Fatalf("rollback: retained EdDSA token refused: %v", err)
	}
	// Without an active key an asymmetric signing alg is refused.
	if err := (JWTSigningConfig{Alg: JWTAlgEdDSA, KeysJSON: back, AcceptHS256: true}).Validate(0); err == nil {
		t.Fatal("asymmetric alg accepted without an active key")
	}
}
