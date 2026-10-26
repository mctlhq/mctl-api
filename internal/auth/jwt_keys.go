package auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/prometheus/client_golang/prometheus"
)

// Access-token signing algorithms this server understands.
const (
	JWTAlgHS256 = "HS256"
	JWTAlgEdDSA = "EdDSA"
	JWTAlgES256 = "ES256"
)

// maxAccessTokenKeys bounds the size of OAUTH_JWT_SIGNING_KEYS.
const maxAccessTokenKeys = 8

// DefaultJWTKeyRetention is how long a retired key stays published and
// verifiable (OAUTH_JWT_KEY_RETENTION).
const DefaultJWTKeyRetention = 2 * time.Hour

var (
	errUnknownKid    = errors.New("JWT kid names no key in the verification set")
	errUnacceptedAlg = errors.New("JWT alg is not accepted")

	oauthJWTVerifications = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "oauth_jwt_verifications_total",
		Help: "Access-token verifications by header alg and result.",
	}, []string{"alg", "result"})
	oauthJWTAudlessAccepted = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "oauth_jwt_audless_accepted_total",
		Help: "HS256 access tokens without an aud claim accepted under the grace rule.",
	})
	oauthJWTSigningKeys = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "oauth_jwt_signing_keys",
		Help: "Access-token signing keys held, by state (active, retained).",
	}, []string{"state"})
)

func init() {
	prometheus.MustRegister(oauthJWTVerifications, oauthJWTAudlessAccepted, oauthJWTSigningKeys)
}

// accessTokenKey is one entry of the signing key set.
type accessTokenKey struct {
	kid       string
	alg       string
	private   crypto.Signer // nil for a retained key whose private half is gone
	public    crypto.PublicKey
	retiredAt time.Time // zero for the active key
}

// accessTokenKeySet holds the active key and the retained ones.
type accessTokenKeySet struct {
	active    *accessTokenKey
	keys      map[string]*accessTokenKey
	retention time.Duration
	now       func() time.Time
}

// signingKeysDoc is the JSON shape of OAUTH_JWT_SIGNING_KEYS.
type signingKeysDoc struct {
	Active string            `json:"active"`
	Keys   []signingKeyEntry `json:"keys"`
}

type signingKeyEntry struct {
	Kid           string     `json:"kid"`
	Alg           string     `json:"alg"`
	PrivateKeyPEM string     `json:"private_key_pem,omitempty"`
	PublicKeyPEM  string     `json:"public_key_pem,omitempty"`
	RetiredAt     *time.Time `json:"retired_at,omitempty"`
}

// parseAccessTokenKeySet parses OAUTH_JWT_SIGNING_KEYS. Errors name the
// offending entry and never carry key material.
func parseAccessTokenKeySet(raw string, retention time.Duration, now func() time.Time) (*accessTokenKeySet, error) {
	if now == nil {
		now = time.Now
	}
	var doc signingKeysDoc
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		// json errors can quote input; report only the position class.
		return nil, errors.New("oauth signing keys: document is not valid JSON of the expected shape")
	}
	if len(doc.Keys) == 0 {
		return nil, errors.New("oauth signing keys: no keys")
	}
	if len(doc.Keys) > maxAccessTokenKeys {
		return nil, fmt.Errorf("oauth signing keys: more than %d keys", maxAccessTokenKeys)
	}
	ks := &accessTokenKeySet{keys: map[string]*accessTokenKey{}, retention: retention, now: now}
	for i, e := range doc.Keys {
		if e.Kid == "" {
			return nil, fmt.Errorf("oauth signing keys: entry #%d: kid is empty", i)
		}
		if _, dup := ks.keys[e.Kid]; dup {
			return nil, fmt.Errorf("oauth signing keys: entry %q: duplicate kid", e.Kid)
		}
		k, err := parseSigningKeyEntry(e)
		if err != nil {
			return nil, fmt.Errorf("oauth signing keys: entry %q: %w", e.Kid, err)
		}
		if e.Kid == doc.Active {
			if k.private == nil {
				return nil, fmt.Errorf("oauth signing keys: entry %q: active key has no private_key_pem", e.Kid)
			}
			if e.RetiredAt != nil {
				return nil, fmt.Errorf("oauth signing keys: entry %q: active key must not carry retired_at", e.Kid)
			}
			ks.active = k
		} else {
			if e.RetiredAt == nil {
				return nil, fmt.Errorf("oauth signing keys: entry %q: retained key needs retired_at", e.Kid)
			}
			k.retiredAt = *e.RetiredAt
		}
		ks.keys[e.Kid] = k
	}
	if ks.active == nil && doc.Active != "" {
		return nil, fmt.Errorf("oauth signing keys: active kid %q names no entry", doc.Active)
	}
	return ks, nil
}

func parseSigningKeyEntry(e signingKeyEntry) (*accessTokenKey, error) {
	if e.Alg != JWTAlgEdDSA && e.Alg != JWTAlgES256 {
		return nil, fmt.Errorf("unsupported alg %q", e.Alg)
	}
	if e.PrivateKeyPEM == "" && e.PublicKeyPEM == "" {
		return nil, errors.New("neither private_key_pem nor public_key_pem is set")
	}
	k := &accessTokenKey{kid: e.Kid, alg: e.Alg}
	if e.PrivateKeyPEM != "" {
		block, _ := pem.Decode([]byte(e.PrivateKeyPEM))
		if block == nil {
			return nil, errors.New("private_key_pem is not PEM")
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.New("private_key_pem is not a PKCS#8 private key")
		}
		signer, ok := parsed.(crypto.Signer)
		if !ok {
			return nil, errors.New("private_key_pem is not a signing key")
		}
		k.private = signer
		k.public = signer.Public()
	}
	if e.PublicKeyPEM != "" {
		block, _ := pem.Decode([]byte(e.PublicKeyPEM))
		if block == nil {
			return nil, errors.New("public_key_pem is not PEM")
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, errors.New("public_key_pem is not a PKIX public key (an HMAC or private key is not accepted here)")
		}
		if k.public != nil && !publicKeysEqual(k.public, parsed) {
			return nil, errors.New("public_key_pem does not match private_key_pem")
		}
		k.public = parsed
	}
	switch e.Alg {
	case JWTAlgEdDSA:
		if _, ok := k.public.(ed25519.PublicKey); !ok {
			return nil, errors.New("alg EdDSA needs an Ed25519 key")
		}
	case JWTAlgES256:
		pk, ok := k.public.(*ecdsa.PublicKey)
		if !ok || pk.Curve != elliptic.P256() {
			return nil, errors.New("alg ES256 needs a P-256 key")
		}
	}
	return k, nil
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	if e, ok := a.(equaler); ok {
		return e.Equal(b)
	}
	return false
}

// usable reports whether the key may still verify and be published.
func (ks *accessTokenKeySet) usable(k *accessTokenKey) bool {
	if k.retiredAt.IsZero() {
		return true
	}
	return k.retiredAt.Add(ks.retention).After(ks.now())
}

// lookup returns the verification key for kid, refusing an unknown or expired
// kid and an alg that does not match the key's type.
func (ks *accessTokenKeySet) lookup(kid, alg string) (*accessTokenKey, error) {
	if ks == nil || kid == "" {
		return nil, errUnknownKid
	}
	k, ok := ks.keys[kid]
	if !ok || !ks.usable(k) {
		return nil, errUnknownKid
	}
	if k.alg != alg {
		return nil, errUnknownKid
	}
	return k, nil
}

// PublicJWKS returns the public parts of the active and retained keys.
func (ks *accessTokenKeySet) PublicJWKS() jose.JSONWebKeySet {
	var set jose.JSONWebKeySet
	kids := make([]string, 0, len(ks.keys))
	for kid := range ks.keys {
		kids = append(kids, kid)
	}
	sort.Strings(kids)
	active, retained := 0, 0
	for _, kid := range kids {
		k := ks.keys[kid]
		if !ks.usable(k) {
			continue
		}
		if k.retiredAt.IsZero() {
			active++
		} else {
			retained++
		}
		set.Keys = append(set.Keys, jose.JSONWebKey{Key: k.public, KeyID: k.kid, Algorithm: k.alg, Use: "sig"})
	}
	oauthJWTSigningKeys.WithLabelValues("active").Set(float64(active))
	oauthJWTSigningKeys.WithLabelValues("retained").Set(float64(retained))
	return set
}

// sign signs input with the key. Ed25519 signs the message; ES256 signs the
// SHA-256 digest and encodes R||S as fixed 32-byte halves (RFC 7518 3.4).
func (k *accessTokenKey) sign(input []byte) ([]byte, error) {
	if k.private == nil {
		return nil, errors.New("signing key has no private half")
	}
	switch k.alg {
	case JWTAlgEdDSA:
		return k.private.Sign(rand.Reader, input, crypto.Hash(0))
	case JWTAlgES256:
		priv, ok := k.private.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("ES256 key is not ECDSA")
		}
		digest := sha256.Sum256(input)
		r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
		if err != nil {
			return nil, err
		}
		out := make([]byte, 64)
		r.FillBytes(out[:32])
		s.FillBytes(out[32:])
		return out, nil
	}
	return nil, fmt.Errorf("unsupported alg %q", k.alg)
}

// JWTSigningConfig is the access-token signing and verification policy.
type JWTSigningConfig struct {
	Audience     string // OAUTH_ACCESS_TOKEN_AUDIENCE; "" selects the base URL
	Alg          string // OAUTH_JWT_SIGNING_ALG; "" selects HS256
	KeysJSON     string // OAUTH_JWT_SIGNING_KEYS; "" means no asymmetric keys
	KeyRetention time.Duration
	AcceptHS256  bool
	RequireAud   bool
}

// Validate checks the combination against the access-token TTL and parses
// the key set, so a bad configuration refuses boot.
func (c JWTSigningConfig) Validate(accessTTL time.Duration) error {
	_, err := c.build(accessTTL, time.Now)
	return err
}

func (c JWTSigningConfig) build(accessTTL time.Duration, now func() time.Time) (*accessTokenKeySet, error) {
	alg := c.Alg
	if alg == "" {
		alg = JWTAlgHS256
	}
	switch alg {
	case JWTAlgHS256, JWTAlgEdDSA, JWTAlgES256:
	default:
		return nil, fmt.Errorf("OAUTH_JWT_SIGNING_ALG must be HS256, EdDSA or ES256, got %q", c.Alg)
	}
	if alg == JWTAlgHS256 && !c.AcceptHS256 {
		return nil, errors.New("OAUTH_JWT_ACCEPT_HS256=false with OAUTH_JWT_SIGNING_ALG=HS256 would refuse every token this server mints")
	}
	retention := c.KeyRetention
	if retention == 0 {
		// Unset: the default, raised to the access-token TTL when that is longer.
		retention = DefaultJWTKeyRetention
		if accessTTL > retention {
			retention = accessTTL
		}
	}
	if accessTTL > 0 && retention < accessTTL {
		return nil, fmt.Errorf("OAUTH_JWT_KEY_RETENTION (%v) must be at least the access token TTL (%v)", retention, accessTTL)
	}
	if strings.TrimSpace(c.KeysJSON) == "" {
		if alg != JWTAlgHS256 {
			return nil, fmt.Errorf("OAUTH_JWT_SIGNING_ALG=%s needs OAUTH_JWT_SIGNING_KEYS", alg)
		}
		return nil, nil
	}
	ks, err := parseAccessTokenKeySet(c.KeysJSON, retention, now)
	if err != nil {
		return nil, fmt.Errorf("OAUTH_JWT_SIGNING_KEYS: %w", err)
	}
	// An empty "active" is allowed only for HS256 (rollback): every entry is
	// then a retained key that keeps verifying outstanding tokens.
	if alg != JWTAlgHS256 && ks.active == nil {
		return nil, errors.New("OAUTH_JWT_SIGNING_KEYS: no active key")
	}
	if alg != JWTAlgHS256 && ks.active.alg != alg {
		return nil, fmt.Errorf("OAUTH_JWT_SIGNING_KEYS: active key %q is %s but OAUTH_JWT_SIGNING_ALG is %s", ks.active.kid, ks.active.alg, alg)
	}
	return ks, nil
}

// ConfigureSigning installs the signing policy. Call it once at startup,
// before the server handles requests.
func (s *OAuthServer) ConfigureSigning(c JWTSigningConfig) error {
	ks, err := c.build(s.AccessTokenTTL, time.Now)
	if err != nil {
		return err
	}
	s.signingAlg = c.Alg
	if s.signingAlg == "" {
		s.signingAlg = JWTAlgHS256
	}
	s.AccessTokenAudience = c.Audience
	s.RejectHS256 = !c.AcceptHS256
	s.RequireAud = c.RequireAud
	s.keys = ks
	if ks != nil {
		ks.PublicJWKS() // seeds the key gauge
	}
	return nil
}

// PublicJWKS returns the published key set, or false when no asymmetric key
// is configured.
func (s *OAuthServer) PublicJWKS() (jose.JSONWebKeySet, bool) {
	if s.keys == nil {
		return jose.JSONWebKeySet{}, false
	}
	return s.keys.PublicJWKS(), true
}
