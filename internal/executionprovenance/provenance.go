// Package executionprovenance defines the execution_attempt_v1 contract: the
// canonical attempt_id and lineage_root of a work-item execution (mctl-api#896).
// It is pure: no I/O and no store, transport or control-plane import.
package executionprovenance

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// ContractVersion is part of every hash input, so a future version can never
// collide with v1 values.
const ContractVersion = "execution_attempt_v1"

// AttemptIDRE and LineageRootRE are the shapes of the derived ids.
var (
	AttemptIDRE   = regexp.MustCompile(`^at_[0-9a-f]{32}$`)
	LineageRootRE = regexp.MustCompile(`^ln_[0-9a-f]{32}$`)
)

// EngineRun is engine_ref up to its first '#': a request-dispatched run is
// attached as <run>#<request_id>, and the request id is not part of the run.
func EngineRun(engineRef string) string {
	if i := strings.IndexByte(engineRef, '#'); i >= 0 {
		return engineRef[:i]
	}
	return engineRef
}

// AttemptID identifies one engine run.
func AttemptID(engine, engineRef string) string {
	return "at_" + digest(CanonicalStrings([]string{ContractVersion, "attempt", engine, EngineRun(engineRef)}))
}

// LineageRoot identifies the root of a resume chain.
func LineageRoot(rootExecutionID string) string {
	return "ln_" + digest(CanonicalStrings([]string{ContractVersion, "lineage", rootExecutionID}))
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])[:32]
}

// CanonicalStrings mirrors Python json.dumps(list, separators=(",", ":"),
// ensure_ascii=True) for an array of strings.
func CanonicalStrings(in []string) []byte {
	var b strings.Builder
	b.WriteByte('[')
	for i, s := range in {
		if i > 0 {
			b.WriteByte(',')
		}
		writeString(&b, s)
	}
	b.WriteByte(']')
	return []byte(b.String())
}

func writeString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\f':
			b.WriteString(`\f`)
		case r >= 0x20 && r <= 0x7e:
			b.WriteRune(r)
		case r >= 0x10000:
			r -= 0x10000
			fmt.Fprintf(b, `\u%04x\u%04x`, 0xd800+(r>>10), 0xdc00+(r&0x3ff))
		default:
			fmt.Fprintf(b, `\u%04x`, r)
		}
	}
	b.WriteByte('"')
}
