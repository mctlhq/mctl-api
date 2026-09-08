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

// Package domains is mctl-api's own system of record for tenant custom
// domains. It replaces the Backstage custom-domains plugin as the write
// path: the plugin's write route requires a Backstage user principal that
// none of mctl-api's callers (GitHub PAT, Dex JWT, the static service
// token, or the MCP tool with no session at all) can ever produce.
package domains

import "time"

// Domain statuses.
const (
	StatusPending  = "pending"
	StatusVerified = "verified"
	StatusActive   = "active"
	StatusFailed   = "failed"
)

// Domain is a single custom-domain registration row.
type Domain struct {
	ID                 string     `json:"id"`
	Team               string     `json:"team"`
	Service            string     `json:"service"`
	Domain             string     `json:"domain"`
	Status             string     `json:"status"`
	VerificationToken  string     `json:"-"`
	CreatedBy          string     `json:"created_by"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
	VerifiedAt         *time.Time `json:"verified_at,omitempty"`
	LastError          string     `json:"last_error,omitempty"`
}
