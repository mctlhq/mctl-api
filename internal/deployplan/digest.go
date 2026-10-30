package deployplan

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
)

// encodingVersion opens the canonical digest encoding, so a future encoding
// can never hash equal to this one. It mirrors the versioned, length-prefixed
// encoding of workitems.intentEncodingVersion.
const encodingVersion = "mctl-deploy-plan/v1"

// DigestInput holds exactly the fields a digest binds. The plan id,
// timestamps, expiry, idempotency key and caller are deliberately absent.
type DigestInput struct {
	Tenant          string
	Service         string
	Environment     string
	IntentCanonical string
	Revision        string
	GitopsBaseSHA   string
	Action          Action
	PreviewID       string
	ValuesAfter     string // canonical YAML of the redacted values
	Host            string
}

// Digest returns "sha256:" + hex of the version line followed by each field
// as "len:value\n", in the fixed documented order.
func Digest(in DigestInput) string {
	h := sha256.New()
	h.Write([]byte(encodingVersion + "\n"))
	for _, f := range []string{
		in.Tenant, in.Service, in.Environment, in.IntentCanonical, in.Revision,
		in.GitopsBaseSHA, string(in.Action), in.PreviewID, in.ValuesAfter, in.Host,
	} {
		h.Write([]byte(strconv.Itoa(len(f)) + ":" + f + "\n"))
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}
