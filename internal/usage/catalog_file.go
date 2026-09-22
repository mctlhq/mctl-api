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

package usage

import (
	"encoding/json"
	"fmt"
	"os"
)

// LoadCatalogFile reads a rate-card file and builds a catalog.
//
// The rates live in a file rather than in this source tree deliberately. A
// published price is a fact about the world with an effective date; baking one
// into a binary means a price change needs a release, and a wrong constant
// silently produces plausible-looking money. A file can be reviewed against the
// provider's own page, versioned in GitOps, and rolled forward without a build.
//
// The expected shape is a JSON array of Pricing entries:
//
//	[
//	  {
//	    "version": "2026-09-01",
//	    "canonical_model": "claude-opus-5",
//	    "provider": "firstParty",
//	    "effective_from": "2026-09-01T00:00:00Z",
//	    "input_per_mtok": 0, "output_per_mtok": 0,
//	    "cache_read_per_mtok": 0, "cache_write_per_mtok": 0,
//	    "web_search_per_call": 0
//	  }
//	]
func LoadCatalogFile(path string) (*Catalog, error) {
	// #nosec G304 -- the path is USAGE_PRICING_CATALOG, supplied by the
	// operator in the deployment manifest alongside the database URL. It is
	// not attacker-influenced, and an operator who can set it can already set
	// the connection string. Scoped to this one call rather than excluded
	// repo-wide, so a future variable-path read still has to justify itself.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("usage: read pricing catalog: %w", err)
	}
	return ParseCatalog(data)
}

// ParseCatalog builds a catalog from the JSON rate-card document.
func ParseCatalog(data []byte) (*Catalog, error) {
	var entries []Pricing
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("usage: parse pricing catalog: %w", err)
	}
	return NewCatalog(entries)
}
