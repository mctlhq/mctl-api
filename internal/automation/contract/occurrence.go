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
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

// OccurrenceKey derives "occ_" + hex(sha256(au_id | definition_version |
// trigger_kind | occurrence_instant_utc_or_event_delivery_id))[:32].
// See docs/automation-contract.md, Identity.
func OccurrenceKey(auID string, definitionVersion int, triggerKind, instantOrDelivery string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{auID, strconv.Itoa(definitionVersion), triggerKind, instantOrDelivery}, "|")))
	return "occ_" + hex.EncodeToString(sum[:])[:32]
}

// OccurrenceKeyAt is OccurrenceKey for a time-based fire; the instant is
// normalised to UTC with nanosecond precision.
func OccurrenceKeyAt(auID string, definitionVersion int, triggerKind string, instant time.Time) string {
	return OccurrenceKey(auID, definitionVersion, triggerKind, instant.UTC().Format(time.RFC3339Nano))
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

// OccurrenceSet models replay detection by occurrence key (isolated-model; the
// durable form is an open question for automation-api-store).
type OccurrenceSet struct{ seen map[string]struct{} }

// Claim records key. A second claim of the same key is a replay and returns
// automation_occurrence_duplicate; it never creates a second work item.
func (s *OccurrenceSet) Claim(key string) error {
	if s.seen == nil {
		s.seen = map[string]struct{}{}
	}
	if _, ok := s.seen[key]; ok {
		return fail(CodeOccurrenceDuplicate, "%s", key)
	}
	s.seen[key] = struct{}{}
	return nil
}
