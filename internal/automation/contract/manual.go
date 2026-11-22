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
	"sync"
)

// ManualRunEnabled gates manual execution. While false, a manual run is
// refused with automation_trigger_unsupported.
const ManualRunEnabled = false

// manualServerOwned are fields a manual-run client may never supply.
var manualServerOwned = []string{"occurrence_key", "principal", "tenant", "au_id", "automation_id"}

// ValidateManualRunRequest checks an automation-manual-run-request.v1 body: a
// client-supplied occurrence_key, principal, tenant or au_id is
// automation_server_owned_field. Claim class: isolated-model.
func ValidateManualRunRequest(raw []byte) error {
	obj, err := parseObject(raw)
	if err != nil {
		return err
	}
	for _, k := range manualServerOwned {
		if _, ok := obj[k]; ok {
			return fail(CodeServerOwnedField, "%s", k)
		}
	}
	if err := checkServerOwned(obj); err != nil {
		return err
	}
	return validateAgainst("automation-manual-run-request.schema.json", obj)
}

// ManualResult is the outcome of a manual submission.
type ManualResult struct {
	OccurrenceKey string
	Replayed      bool
}

type manualKey struct{ principal, tenant, auID, key string }

// ManualRequests models manual-run idempotency, keyed (principal, tenant,
// au_id, idempotency_key) with a body hash. Isolated-model, no production caller.
type ManualRequests struct {
	mu   sync.Mutex
	seen map[manualKey]manualEntry
}

type manualEntry struct{ bodyHash, occ string }

// Submit validates the body and derives the occurrence. The same key and body
// replays; the same key with a different body is automation_idempotency_key_reused.
// Execution itself is refused while ManualRunEnabled is false, after the
// request has been judged.
func (m *ManualRequests) Submit(principal, tenant, auID string, raw []byte) (ManualResult, error) {
	if err := ValidateManualRunRequest(raw); err != nil {
		return ManualResult{}, err
	}
	obj, _ := parseObject(raw)
	callerKey, _ := obj["idempotency_key"].(string)
	src, err := ManualSource(principal, tenant, callerKey)
	if err != nil {
		return ManualResult{}, err
	}
	occ, err := OccurrenceKey(auID, "manual", src)
	if err != nil {
		return ManualResult{}, err
	}
	sum := sha256.Sum256(raw)
	h := hex.EncodeToString(sum[:])
	k := manualKey{principal, tenant, auID, callerKey}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seen == nil {
		m.seen = map[manualKey]manualEntry{}
	}
	if e, ok := m.seen[k]; ok {
		if e.bodyHash != h {
			return ManualResult{}, fail(CodeIdempotencyKeyReused, "manual run idempotency key")
		}
		return ManualResult{OccurrenceKey: e.occ, Replayed: true}, nil
	}
	m.seen[k] = manualEntry{h, occ}
	return ManualResult{OccurrenceKey: occ}, nil
}

// ExecuteManual refuses execution while manual runs are not gated on.
func ExecuteManual(ManualResult) error {
	if !ManualRunEnabled {
		return fail(CodeTriggerUnsupported, "manual run execution")
	}
	return nil
}
