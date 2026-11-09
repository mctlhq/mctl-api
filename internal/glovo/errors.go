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

// Package glovo holds the fail-closed authorization gate of the Glovo MCP
// facade. No route uses it yet.
package glovo

import (
	"encoding/json"
	"net/http"
)

// Code is a stable Glovo error code.
type Code string

const (
	CodeNotReady      Code = "not_ready"
	CodeNotAuthorized Code = "not_authorized"
)

// Error is a typed Glovo refusal.
type Error struct {
	Code        Code
	Description string
}

func (e *Error) Error() string { return string(e.Code) + ": " + e.Description }

// Is matches another *Error with the same code.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t != nil && e != nil && t.Code == e.Code
}

// WriteError writes e as {"error","error_description"}: not_ready is 503,
// not_authorized 403.
func WriteError(w http.ResponseWriter, e *Error) {
	status := http.StatusForbidden
	if e.Code == CodeNotReady {
		status = http.StatusServiceUnavailable
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             string(e.Code),
		"error_description": e.Description,
	})
}
