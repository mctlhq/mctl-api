package deployplan

import (
	"crypto/sha256"
	"encoding/base32"
	"strings"
)

// PreviewID derives the 6-character [a-z0-9] preview id deterministically
// from the plan's identity, like the workflow's id (the last six [a-z0-9] of
// the Argo workflow name) but stable across repeated planning.
func PreviewID(tenant, service, revision, gitopsBase string) string {
	h := sha256.New()
	h.Write([]byte("mctl-preview-id/v1\x00"))
	for _, f := range []string{tenant, service, revision, gitopsBase} {
		h.Write([]byte(f))
		h.Write([]byte{0})
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(h.Sum(nil))
	// The base32 alphabet is A-Z and 2-7, so lower-casing stays in [a-z0-9].
	return strings.ToLower(enc[:6])
}

// Host is the preview hostname: {service}-{id}.{domain}, as the workflow
// builds it.
func Host(service, previewID, platformDomain string) string {
	return service + "-" + previewID + "." + platformDomain
}
