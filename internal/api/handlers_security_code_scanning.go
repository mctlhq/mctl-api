// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package api

// GitHub Code Scanning receiver for SecurityFinding v1 (mctl-api#802, part of
// mctlhq/mctl-gitops#2103). It is a thin authenticated adapter between the
// repository webhook event `code_scanning_alert` and the #774 store:
//
//   - the dedicated HMAC secret is the channel credential;
//   - provider ref, principal, tenant and strength come from server
//     configuration only, never from the payload;
//   - payload prose is bounded untrusted evidence;
//   - an allowlisted delivery is answered 2xx only once the store reports
//     created or duplicate.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/securityfindings"
)

const (
	// CodeScanningProviderRef is the route-bound provider ref.
	CodeScanningProviderRef = "github-code-scanning"
	// CodeScanningMinSecretLen is the shortest accepted dedicated secret.
	CodeScanningMinSecretLen = 32

	codeScanningStoreTimeout = 5 * time.Second
	maxCodeScanningDelivery  = 128
)

// Webhook delivery results, a closed label set.
const (
	csResultAccepted         = "accepted"
	csResultDuplicate        = "duplicate"
	csResultIgnored          = "ignored"
	csResultSignatureInvalid = "signature_invalid"
	csResultStoreUnavailable = "store_unavailable"
	csResultRejected         = "rejected"
)

var securityWebhookDeliveries = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "mctl_security_webhook_deliveries_total",
	Help: "Security provider webhook deliveries by provider and result (mctl-api#802).",
}, []string{"provider", "result"})

func init() {
	prometheus.MustRegister(securityWebhookDeliveries)
	for _, r := range []string{csResultAccepted, csResultDuplicate, csResultIgnored, csResultSignatureInvalid, csResultStoreUnavailable, csResultRejected} {
		securityWebhookDeliveries.WithLabelValues(CodeScanningProviderRef, r).Add(0)
	}
}

// SecurityIngester is the part of the #774 store the receiver calls.
type SecurityIngester interface {
	IngestBatch(ctx context.Context, pc securityfindings.ProviderContext, batch securityfindings.Batch) ([]securityfindings.ItemResult, error)
}

// codeScanningActionMap pins the supported `code_scanning_alert` actions of
// the GitHub webhook documentation (appeared_in_branch, closed_by_user,
// created, fixed, reopened, reopened_by_user) to claimed actions.
var codeScanningActionMap = map[string]string{
	"created":            securityfindings.ClaimPresent,
	"appeared_in_branch": securityfindings.ClaimPresent,
	"reopened":           securityfindings.ClaimPresent,
	"reopened_by_user":   securityfindings.ClaimPresent,
	"fixed":              securityfindings.ClaimFixed,
	"closed_by_user":     securityfindings.ClaimWithdrawn,
}

// codeScanningUserActions are performed by a person in the UI; GitHub carries
// no analysed commit or ref for them.
var codeScanningUserActions = map[string]bool{"closed_by_user": true, "reopened_by_user": true}

// CodeScanningConfig is the non-secret SECURITY_GITHUB_CODE_SCANNING value.
type CodeScanningConfig struct {
	ProviderRef  string            `json:"provider_ref"`
	Repositories map[string]string `json:"repositories"` // repository full name -> tenant
	Tools        []string          `json:"tools"`
	Actions      []string          `json:"actions"`
}

// ParseCodeScanningConfig validates raw against the configured security
// providers. Every error means the receiver must stay disabled.
func ParseCodeScanningConfig(raw string, providers map[string]auth.SecurityProviderConfig) (*CodeScanningConfig, error) {
	var cfg CodeScanningConfig
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &cfg); err != nil {
		return nil, fmt.Errorf("parse SECURITY_GITHUB_CODE_SCANNING: %w", err)
	}
	if cfg.ProviderRef == "" {
		cfg.ProviderRef = CodeScanningProviderRef
	}
	if cfg.ProviderRef != CodeScanningProviderRef {
		return nil, fmt.Errorf("SECURITY_GITHUB_CODE_SCANNING: provider_ref must be %q", CodeScanningProviderRef)
	}
	prov, ok := providers[CodeScanningProviderRef]
	if !ok {
		return nil, fmt.Errorf("SECURITY_PROVIDERS has no %q entry", CodeScanningProviderRef)
	}
	if _, err := securityfindings.ParseStrength(prov.MaxStrength); err != nil {
		return nil, fmt.Errorf("SECURITY_PROVIDERS %q: %w", CodeScanningProviderRef, err)
	}
	if len(cfg.Repositories) == 0 || len(cfg.Tools) == 0 || len(cfg.Actions) == 0 {
		return nil, errors.New("SECURITY_GITHUB_CODE_SCANNING: repositories, tools and actions must not be empty")
	}
	repos := make(map[string]string, len(cfg.Repositories))
	for repo, tenant := range cfg.Repositories {
		repo, tenant = strings.ToLower(strings.TrimSpace(repo)), strings.TrimSpace(tenant)
		if repo == "" || tenant == "" {
			return nil, errors.New("SECURITY_GITHUB_CODE_SCANNING: empty repository or tenant")
		}
		if !containsString(prov.Tenants, tenant) {
			return nil, fmt.Errorf("SECURITY_GITHUB_CODE_SCANNING: tenant %q is not a tenant of provider %q", tenant, CodeScanningProviderRef)
		}
		repos[repo] = tenant
	}
	cfg.Repositories = repos
	for i, t := range cfg.Tools {
		cfg.Tools[i] = strings.ToLower(strings.TrimSpace(t))
		if cfg.Tools[i] == "" {
			return nil, errors.New("SECURITY_GITHUB_CODE_SCANNING: empty tool")
		}
	}
	for i, a := range cfg.Actions {
		cfg.Actions[i] = strings.TrimSpace(a)
		if _, ok := codeScanningActionMap[cfg.Actions[i]]; !ok {
			return nil, fmt.Errorf("SECURITY_GITHUB_CODE_SCANNING: unknown action %q", a)
		}
	}
	return &cfg, nil
}

// CodeScanningSecretUsable reports whether secret may be the dedicated
// receiver secret: long enough and distinct from the org webhook secret.
func CodeScanningSecretUsable(secret, orgWebhookSecret string) bool {
	return len(secret) >= CodeScanningMinSecretLen && secret != orgWebhookSecret
}

func (c *CodeScanningConfig) toolAllowed(name string) bool {
	return containsString(c.Tools, strings.ToLower(strings.TrimSpace(name)))
}

// codeScanningPayload lists the only fields read from a code_scanning_alert
// delivery.
type codeScanningPayload struct {
	Action    string `json:"action"`
	Ref       string `json:"ref"`
	CommitOID string `json:"commit_oid"`
	Alert     *struct {
		Number  int64  `json:"number"`
		HTMLURL string `json:"html_url"`
		Rule    struct {
			ID                    string `json:"id"`
			Severity              string `json:"severity"`
			SecuritySeverityLevel string `json:"security_severity_level"`
			Description           string `json:"description"`
		} `json:"rule"`
		Tool struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"tool"`
		MostRecentInstance struct {
			Ref       string `json:"ref"`
			CommitSHA string `json:"commit_sha"`
			Location  struct {
				Path      string `json:"path"`
				StartLine int    `json:"start_line"`
				EndLine   int    `json:"end_line"`
			} `json:"location"`
			Message struct {
				Text string `json:"text"`
			} `json:"message"`
		} `json:"most_recent_instance"`
	} `json:"alert"`
	Repository *struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
}

var commitSHARe = regexp.MustCompile(`^[0-9a-fA-F]{40}([0-9a-fA-F]{24})?$`)

// mapCodeScanningAlert is the pure mapping of a decoded, allowlisted delivery
// to one observation. repoKey is the normalized repository name.
func mapCodeScanningAlert(p *codeScanningPayload, repoKey, tenant, deliveryID string) (securityfindings.ObservationInput, error) {
	a := p.Alert
	inst := a.MostRecentInstance
	switch {
	case deliveryID == "" || len(deliveryID) > maxCodeScanningDelivery:
		return securityfindings.ObservationInput{}, errors.New("X-GitHub-Delivery is required")
	case a.Number <= 0:
		return securityfindings.ObservationInput{}, errors.New("alert.number is required")
	case strings.TrimSpace(a.Rule.ID) == "":
		return securityfindings.ObservationInput{}, errors.New("alert.rule.id is required")
	case strings.TrimSpace(inst.Location.Path) == "":
		return securityfindings.ObservationInput{}, errors.New("alert.most_recent_instance.location.path is required")
	}
	location := ""
	if inst.Location.StartLine > 0 {
		end := inst.Location.EndLine
		if end <= 0 {
			end = inst.Location.StartLine
		}
		location = strconv.Itoa(inst.Location.StartLine) + ":" + strconv.Itoa(end)
	}
	revision := ""
	if !codeScanningUserActions[p.Action] {
		switch {
		case commitSHARe.MatchString(p.CommitOID):
			revision = strings.ToLower(p.CommitOID)
		case commitSHARe.MatchString(inst.CommitSHA):
			revision = strings.ToLower(inst.CommitSHA)
		}
	}
	rule := strings.TrimSpace(a.Rule.ID)
	sev := a.Rule.SecuritySeverityLevel
	if sev == "" {
		sev = a.Rule.Severity
	}
	obs := securityfindings.ObservationInput{
		Tenant:          tenant,
		Identity:        rule,
		SourceFindingID: "github:" + repoKey + "/code-scanning/" + strconv.FormatInt(a.Number, 10),
		Subject: securityfindings.Subject{
			Repository: repoKey, Path: strings.TrimSpace(inst.Location.Path), Location: location, RuleID: rule,
		},
		ClaimedAction:    codeScanningActionMap[p.Action],
		ObservedRevision: revision,
		Untrusted: securityfindings.Untrusted{
			Title:           truncate(a.Rule.Description, securityfindings.MaxUntrustedTitle),
			Severity:        truncate(sev, securityfindings.MaxUntrustedSeverity),
			ClaimedProvider: truncate(strings.TrimSpace(a.Tool.Name+" "+a.Tool.Version), securityfindings.MaxUntrustedProvider),
			Description: truncate(fmt.Sprintf("action=%s ref=%s message=%s", p.Action,
				firstNonEmpty(p.Ref, inst.Ref), inst.Message.Text), securityfindings.MaxUntrustedDescripton),
		},
	}
	if strings.HasPrefix(a.HTMLURL, "https://github.com/") && len(a.HTMLURL) <= securityfindings.MaxRefLen {
		obs.EvidenceRefs = []securityfindings.EvidenceRef{{Kind: "github-code-scanning-alert", Ref: a.HTMLURL}}
	}
	return obs, nil
}

func (h *Handlers) csResult(w http.ResponseWriter, status int, result string, extra map[string]string) {
	securityWebhookDeliveries.WithLabelValues(CodeScanningProviderRef, result).Inc()
	body := map[string]string{"status": result}
	for k, v := range extra {
		body[k] = v
	}
	writeJSON(w, status, body)
}

// codeScanningReady re-checks the receiver's configuration and returns the
// server-derived provider context.
func (h *Handlers) codeScanningReady() (securityfindings.ProviderContext, bool) {
	o := h.opts
	if o.CodeScanningConfig == nil || !CodeScanningSecretUsable(o.CodeScanningWebhookSecret, o.GitHubWebhookSecret) {
		return securityfindings.ProviderContext{}, false
	}
	prov, ok := o.SecurityProviders[CodeScanningProviderRef]
	if !ok {
		return securityfindings.ProviderContext{}, false
	}
	max, err := securityfindings.ParseStrength(prov.MaxStrength)
	if err != nil {
		return securityfindings.ProviderContext{}, false
	}
	return securityfindings.ProviderContext{
		Ref:         CodeScanningProviderRef,
		PrincipalID: auth.SecurityProviderUserPrefix + CodeScanningProviderRef,
		MaxStrength: max,
		Tenants:     append([]string(nil), prov.Tenants...),
	}, true
}

// HandleGitHubCodeScanningWebhook handles
// POST /api/v1/security/webhooks/github-code-scanning.
func (h *Handlers) HandleGitHubCodeScanningWebhook(w http.ResponseWriter, r *http.Request) {
	pc, ready := h.codeScanningReady()
	if !ready {
		writeError(w, http.StatusServiceUnavailable, "code scanning webhook receiver not configured")
		return
	}
	cfg := h.opts.CodeScanningConfig
	body, err := io.ReadAll(io.LimitReader(r.Body, maxGitHubWebhookBytes+1))
	if err != nil {
		h.csResult(w, http.StatusBadRequest, csResultRejected, map[string]string{"reason": "failed to read body"})
		return
	}
	if len(body) > maxGitHubWebhookBytes {
		h.csResult(w, http.StatusRequestEntityTooLarge, csResultRejected, map[string]string{"reason": "payload too large"})
		return
	}
	if !validGitHubSignature(h.opts.CodeScanningWebhookSecret, body, r.Header.Get("X-Hub-Signature-256")) {
		h.csResult(w, http.StatusUnauthorized, csResultSignatureInvalid, map[string]string{"reason": "invalid signature"})
		return
	}
	if r.Header.Get("X-GitHub-Event") != "code_scanning_alert" {
		h.csResult(w, http.StatusAccepted, csResultIgnored, map[string]string{"reason": "event not handled"})
		return
	}
	var p codeScanningPayload
	if err := json.Unmarshal(body, &p); err != nil {
		h.csResult(w, http.StatusBadRequest, csResultRejected, map[string]string{"reason": "invalid json payload"})
		return
	}
	if !containsString(cfg.Actions, p.Action) {
		h.csResult(w, http.StatusAccepted, csResultIgnored, map[string]string{"reason": "action not allowed"})
		return
	}
	if p.Repository == nil {
		h.csResult(w, http.StatusAccepted, csResultIgnored, map[string]string{"reason": "repository not allowed"})
		return
	}
	repoKey := strings.ToLower(strings.TrimSpace(p.Repository.FullName))
	tenant, ok := cfg.Repositories[repoKey]
	if !ok {
		h.csResult(w, http.StatusAccepted, csResultIgnored, map[string]string{"reason": "repository not allowed"})
		return
	}
	if p.Alert == nil {
		h.csResult(w, http.StatusBadRequest, csResultRejected, map[string]string{"reason": "alert is required"})
		return
	}
	if !cfg.toolAllowed(p.Alert.Tool.Name) {
		h.csResult(w, http.StatusAccepted, csResultIgnored, map[string]string{"reason": "tool not allowed"})
		return
	}
	delivery := strings.TrimSpace(r.Header.Get("X-GitHub-Delivery"))
	obs, err := mapCodeScanningAlert(&p, repoKey, tenant, delivery)
	if err != nil {
		h.csResult(w, http.StatusBadRequest, csResultRejected, map[string]string{"reason": err.Error()})
		return
	}
	ing := h.opts.CodeScanningIngester
	if ing == nil {
		h.csResult(w, http.StatusServiceUnavailable, csResultStoreUnavailable, nil)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), codeScanningStoreTimeout)
	defer cancel()
	results, err := ing.IngestBatch(ctx, pc, securityfindings.Batch{DeliveryID: delivery, Observations: []securityfindings.ObservationInput{obs}})
	if err != nil || len(results) != 1 {
		slog.Error("code scanning webhook: store unavailable", "delivery", delivery, "repository", repoKey, "error", err)
		h.csResult(w, http.StatusServiceUnavailable, csResultStoreUnavailable, nil)
		return
	}
	res := results[0]
	switch {
	case res.Status == securityfindings.ItemCreated || res.Status == securityfindings.ItemDuplicate:
		result := csResultAccepted
		if res.Status == securityfindings.ItemDuplicate {
			result = csResultDuplicate
		}
		h.auditSecurity(r, auth.NewSecurityProviderUser(CodeScanningProviderRef), "observations.webhook", map[string]string{
			"principal_id": pc.PrincipalID, "delivery_id": delivery, "repository": repoKey, "result": result,
		})
		h.csResult(w, http.StatusAccepted, result, nil)
	case res.Status == securityfindings.ItemRejected && res.Code != securityfindings.CodeInternal:
		h.csResult(w, http.StatusUnprocessableEntity, csResultRejected, map[string]string{"code": res.Code})
	default:
		// internal_error or an unknown status: never acknowledged.
		slog.Error("code scanning webhook: store did not accept", "delivery", delivery, "repository", repoKey, "status", res.Status, "code", res.Code)
		h.csResult(w, http.StatusServiceUnavailable, csResultStoreUnavailable, nil)
	}
}
