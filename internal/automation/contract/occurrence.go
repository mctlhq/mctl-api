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

package contract

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"time"
)

// OccurrenceDomain is the domain-separation tag hashed first into every
// occurrence key.
const OccurrenceDomain = "mctl.automation.occurrence.v1"

// OccurrenceSource is the identity of what caused one fire. It is built only
// through the constructors below, so the parts are never empty. Its encoding
// carries a kind tag, so an event source and a manual source with the same
// parts never collide.
type OccurrenceSource struct {
	kind  string
	parts []string
}

func newSource(kind string, parts ...string) (OccurrenceSource, error) {
	for _, p := range parts {
		if p == "" {
			return OccurrenceSource{}, fail(CodeInvalid, "occurrence source component is empty")
		}
	}
	return OccurrenceSource{kind: kind, parts: parts}, nil
}

// ScheduledSource is the source of an "at" or "schedule" fire: the scheduled
// instant, normalised to UTC RFC 3339 with nanosecond precision.
func ScheduledSource(instant time.Time) (OccurrenceSource, error) {
	if instant.IsZero() {
		return OccurrenceSource{}, fail(CodeInvalid, "occurrence source component is empty")
	}
	return newSource("scheduled", instant.UTC().Format(time.RFC3339Nano))
}

// EventSource is the source of an "event" or "dependency" fire: the
// authenticated producer, the event type and the stable producer event id. A
// per-delivery or transport id must never be passed as stableID.
func EventSource(producer, eventType, stableID string) (OccurrenceSource, error) {
	return newSource("event", producer, eventType, stableID)
}

// ManualSource is the source of a manual run: the server-bound principal and
// tenant and the caller's opaque idempotency key. A client never supplies an
// occurrence id.
func ManualSource(principal, tenant, callerKey string) (OccurrenceSource, error) {
	return newSource("manual", principal, tenant, callerKey)
}

func appendField(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s))) //nolint:gosec // callers pass short identifiers; a part over 4 GiB is impractical, and the durable store must bound inputs itself
	return append(b, s...)
}

// OccurrenceKey derives "occ_" + hex(sha256(domain || len-prefixed(au_id,
// trigger_kind, source kind, source parts...)))[:32]. The definition version is
// deliberately not an input: a replay across an update is the same occurrence.
// See docs/automation-contract.md, section 2. Claim class: isolated-model.
func OccurrenceKey(auID, triggerKind string, src OccurrenceSource) (string, error) {
	if auID == "" || triggerKind == "" || src.kind == "" {
		return "", fail(CodeInvalid, "occurrence source component is empty")
	}
	b := appendField(nil, OccurrenceDomain)
	b = appendField(b, auID)
	b = appendField(b, triggerKind)
	b = appendField(b, src.kind)
	for _, p := range src.parts {
		b = appendField(b, p)
	}
	sum := sha256.Sum256(b)
	return "occ_" + hex.EncodeToString(sum[:])[:32], nil
}

// ExternalKey is the per-fire WorkItem external_key.
func ExternalKey(auID, occurrenceKey string) string {
	return "automation:" + auID + ":" + occurrenceKey
}

// FireIdempotencyKey is the per-fire WorkItem idempotency key. It is derived,
// never chosen by a client.
func FireIdempotencyKey(occurrenceKey string) string {
	return "automation-fire:" + occurrenceKey
}
