// Copyright 2026 MCTL Authors
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

package bridge

import (
	"fmt"

	"github.com/mctlhq/mctl-api/internal/jcs"
)

// rawCheck is the #1059 raw-bytes pre-check, run on a v1alpha2 result body
// before any json.Unmarshal. It is a thin wrapper over jcs.PrecheckIntegers
// (#988): duplicate keys, lone surrogates, non-finite or out-of-range numbers
// and every non-integer token are refused as invalid_document. Every number of
// the v1alpha2 contract is an integer.
func rawCheck(raw []byte) error {
	if err := jcs.PrecheckIntegers(raw); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidDocument, err)
	}
	return nil
}
