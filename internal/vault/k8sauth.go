package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// TokenProvider supplies the token used for Vault API calls.
//
// A single long-lived static token cannot recover if it is revoked out from
// under the process — see the 2026-08-01 Backstage incident, where exactly
// that happened and every Vault-backed route returned 500 until a human
// noticed and minted a new one by hand. A provider lets the caller recover
// on its own instead.
type TokenProvider interface {
	// GetToken returns the current token, logging in or refreshing if needed.
	GetToken(ctx context.Context) (string, error)
	// Invalidate discards the cached token, but only if it is still
	// rejected — the exact token Vault turned down.
	//
	// The scoping matters under concurrency: several in-flight requests can
	// each get a 403 for the same dead token, and the first one to notice
	// logs in and caches a fresh one. An unconditional invalidate would let
	// the stragglers throw that fresh token away and log in again, one
	// after another, turning a single revocation into a login storm.
	// Comparing first makes every straggler a no-op.
	Invalidate(rejected string)
}

// staticTokenProvider wraps a pre-issued token. Nothing to refresh —
// Invalidate is a no-op.
type staticTokenProvider struct {
	token string
}

// NewStaticTokenProvider wraps a pre-issued token as a TokenProvider.
func NewStaticTokenProvider(token string) TokenProvider {
	return &staticTokenProvider{token: token}
}

func (p *staticTokenProvider) GetToken(context.Context) (string, error) {
	return p.token, nil
}

func (p *staticTokenProvider) Invalidate(string) {}

const defaultJWTPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

// renewAt is the fraction of the lease at which to proactively re-login.
// Vault hands out leases in the minutes-to-hours range here, so this leaves
// a wide margin for clock skew and a slow login without re-authenticating
// on every request.
const renewAt = 0.8

// KubernetesAuthOptions configures a Kubernetes-auth TokenProvider.
type KubernetesAuthOptions struct {
	VaultAddr string
	// Role is the Vault role bound to this pod's ServiceAccount.
	Role string
	// AuthPath is the auth mount path, without leading/trailing slashes.
	// Defaults to "kubernetes".
	AuthPath string
	// JWTPath is the projected ServiceAccount token file. Defaults to the
	// standard Kubernetes path.
	JWTPath string
	// HTTPClient is injectable for tests; defaults to a client with a 15s
	// timeout.
	HTTPClient *http.Client
	// ReadJWT is injectable for tests; defaults to reading JWTPath from disk.
	ReadJWT func(path string) (string, error)
	// Now is injectable for tests; defaults to time.Now.
	Now    func() time.Time
	Logger *slog.Logger
}

type cachedToken struct {
	token      string
	renewAfter time.Time
	// hardExpiry is the lease's actual end, distinct from renewAfter (the
	// soft 80% renewal trigger). A renewal attempt that fails before
	// hardExpiry can still fall back to this token instead of erroring out.
	hardExpiry time.Time
}

// loginAttempt is a single in-flight (or just-finished) login round.
// result/err are written exactly once, by the goroutine that owns the
// attempt, before it closes done — followers only ever read them after
// receiving from done, which happens-after that write, so this needs no
// extra locking despite being read from multiple goroutines.
type loginAttempt struct {
	done   chan struct{}
	result string
	err    error
}

type kubernetesTokenProvider struct {
	opts KubernetesAuthOptions

	mu     sync.Mutex
	cached *cachedToken
	// inFlight is non-nil while a login is in progress; concurrent callers
	// wait on it instead of starting their own.
	inFlight *loginAttempt
}

// NewKubernetesTokenProvider authenticates to Vault with the pod's projected
// ServiceAccount JWT.
//
// The JWT is re-read from disk on every login: kubelet rotates projected
// tokens in place, so a copy cached at startup goes stale and Vault starts
// rejecting it.
func NewKubernetesTokenProvider(opts KubernetesAuthOptions) TokenProvider {
	if opts.AuthPath == "" {
		opts.AuthPath = "kubernetes"
	}
	if opts.JWTPath == "" {
		opts.JWTPath = defaultJWTPath
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{Timeout: 15 * time.Second}
	}
	if opts.ReadJWT == nil {
		opts.ReadJWT = func(path string) (string, error) {
			b, err := os.ReadFile(path)
			if err != nil {
				return "", err
			}
			return string(b), nil
		}
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	return &kubernetesTokenProvider{opts: opts}
}

type kubernetesLoginResponse struct {
	Auth *struct {
		ClientToken   string `json:"client_token"`
		LeaseDuration int    `json:"lease_duration"`
	} `json:"auth"`
	Errors []string `json:"errors"`
}

func (p *kubernetesTokenProvider) login(ctx context.Context) (string, error) {
	jwt, err := p.opts.ReadJWT(p.opts.JWTPath)
	if err != nil {
		return "", fmt.Errorf("vault k8s auth: reading ServiceAccount token: %w", err)
	}
	jwt = strings.TrimSpace(jwt)
	if jwt == "" {
		return "", fmt.Errorf("vault k8s auth: empty ServiceAccount token at %s", p.opts.JWTPath)
	}

	body, err := json.Marshal(map[string]string{"role": p.opts.Role, "jwt": jwt})
	if err != nil {
		return "", fmt.Errorf("vault k8s auth: encoding login request: %w", err)
	}

	url := strings.TrimRight(p.opts.VaultAddr, "/") + "/v1/auth/" + p.opts.AuthPath + "/login"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("vault k8s auth: building login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.opts.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("vault k8s auth: login request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	var parsed kubernetesLoginResponse
	// Vault puts the actionable part in the body — "role not found",
	// "service account name not authorized", "JWT validation failed" all
	// arrive as the same HTTP status. Losing it would leave a production
	// auth failure diagnosable only by guessing. A non-JSON body (a proxy
	// error page, say) just means the status stands alone.
	_ = json.NewDecoder(resp.Body).Decode(&parsed)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		detail := strings.Join(parsed.Errors, "; ")
		if detail != "" {
			return "", fmt.Errorf("vault k8s auth failed for role %q: HTTP %d — %s", p.opts.Role, resp.StatusCode, detail)
		}
		return "", fmt.Errorf("vault k8s auth failed for role %q: HTTP %d", p.opts.Role, resp.StatusCode)
	}

	if parsed.Auth == nil || parsed.Auth.ClientToken == "" {
		return "", fmt.Errorf("vault k8s auth for role %q returned no client_token", p.opts.Role)
	}

	// A zero/absent lease means a root-ish token with no expiry; re-login
	// hourly anyway so a revoked one self-heals.
	leaseSeconds := parsed.Auth.LeaseDuration
	if leaseSeconds <= 0 {
		leaseSeconds = 3600
	}

	now := p.opts.Now()
	p.mu.Lock()
	p.cached = &cachedToken{
		token:      parsed.Auth.ClientToken,
		renewAfter: now.Add(time.Duration(float64(leaseSeconds) * renewAt * float64(time.Second))),
		hardExpiry: now.Add(time.Duration(leaseSeconds) * time.Second),
	}
	p.mu.Unlock()

	p.opts.Logger.Info("vault kubernetes auth succeeded", "role", p.opts.Role, "lease_duration", leaseSeconds)
	return parsed.Auth.ClientToken, nil
}

func (p *kubernetesTokenProvider) GetToken(ctx context.Context) (string, error) {
	p.mu.Lock()
	if p.cached != nil && p.opts.Now().Before(p.cached.renewAfter) {
		token := p.cached.token
		p.mu.Unlock()
		return token, nil
	}
	// A proactive renewal (past renewAfter, i.e. 80% of the lease) can fail
	// for reasons that have nothing to do with the old token's validity — a
	// blip on the Kubernetes TokenReview API, say — while Vault's KV
	// endpoint stays healthy. The old token is still good for the
	// remaining 20% of its lease, so keep serving it instead of turning a
	// transient renewal hiccup into a hard outage.
	fallback := p.cached

	if p.inFlight != nil {
		attempt := p.inFlight
		p.mu.Unlock()
		<-attempt.done
		return attempt.result, attempt.err
	}

	attempt := &loginAttempt{done: make(chan struct{})}
	p.inFlight = attempt
	p.mu.Unlock()

	token, err := p.login(ctx)
	if err != nil {
		if fallback != nil && p.opts.Now().Before(fallback.hardExpiry) {
			p.opts.Logger.Warn("vault kubernetes auth renewal failed; reusing the still-valid cached token until its lease expires",
				"role", p.opts.Role, "error", err.Error())
			token, err = fallback.token, nil
		} else {
			// No usable fallback — either this is the first login ever, or
			// the old token's lease has actually run out. Drop it so the
			// cache never holds a token we already know Vault will refuse.
			p.mu.Lock()
			p.cached = nil
			p.mu.Unlock()
		}
	}

	attempt.result, attempt.err = token, err

	p.mu.Lock()
	p.inFlight = nil
	p.mu.Unlock()
	close(attempt.done)

	return token, err
}

func (p *kubernetesTokenProvider) Invalidate(rejected string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cached != nil && p.cached.token == rejected {
		p.cached = nil
	}
}
