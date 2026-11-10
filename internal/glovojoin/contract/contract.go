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

// Package contract is the frozen wire contract glovo-facade-mctl-api/v1alpha1
// between the mctl-telegram Glovo facade and mctl-api (mctl-api#957 design 7).
// The JSON document is embedded; Version and Digest pin it. The test in this
// package fails on any byte change that is not matched by a new Digest, and the
// golden fixtures under testdata/ are replayed against the real handlers.
package contract

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
)

// Version is the contract version carried in GET /compatibility and recorded
// in the document.
const Version = "glovo-facade-mctl-api/v1alpha1"

// Digest is the sha256 of the embedded document, "sha256:<hex>". Changing the
// document requires changing this constant, and a changed document under the
// same Version is a review failure: bump the version with the digest.
const Digest = "sha256:00d6a8f2ff376d1b6f86fb8a510864cb4c0fb8dc8689793768f06bae17765ec5"

// BasePath is the route prefix every join route lives under.
const BasePath = "/api/v1/assistants/glovo/v1alpha1"

//go:embed glovo-facade-mctl-api.v1alpha1.json
var raw []byte

// JSON returns a copy of the embedded document.
func JSON() []byte { return append([]byte(nil), raw...) }

// ComputedDigest is the sha256 of the embedded document.
func ComputedDigest() string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Route is one row of the frozen route matrix.
type Route struct {
	ID            string          `json:"id"`
	Method        string          `json:"method"`
	Path          string          `json:"path"`
	Scope         string          `json:"scope"`
	Tool          *string         `json:"tool"`
	Request       json.RawMessage `json:"request"`
	Response      json.RawMessage `json:"response"`
	NeedsScopeRef bool            `json:"needs_scope_ref"`
	Idempotent    bool            `json:"idempotent"`
}

// Code is one row of the code table: the internal code, its HTTP status and
// the wire code the facade sees.
type Code struct {
	Code   string `json:"code"`
	Status int    `json:"status"`
	Wire   string `json:"wire"`
}

// Condition is one row of the condition table.
type Condition struct {
	Reason string `json:"reason"`
	Code   string `json:"code"`
	Status int    `json:"status"`
}

// Document is the parsed contract.
type Document struct {
	Contract string  `json:"contract"`
	Version  string  `json:"version"`
	BasePath string  `json:"base_path"`
	Routes   []Route `json:"routes"`
	Errors   struct {
		FacadeCodes []string        `json:"facade_codes"`
		Codes       []Code          `json:"codes"`
		Conditions  []Condition     `json:"conditions"`
		Body        json.RawMessage `json:"body"`
	} `json:"errors"`
	Limits struct {
		PerSubjectPerMinute       int `json:"per_subject_per_minute"`
		WritesPerSubjectPerMinute int `json:"writes_per_subject_per_minute"`
		FacadeAggregatePerMinute  int `json:"facade_aggregate_per_minute"`
	} `json:"limits"`
	Timeouts struct {
		RequestSeconds int `json:"request_seconds"`
	} `json:"timeouts"`
	OAuth struct {
		Resource        string   `json:"resource"`
		ScopesSupported []string `json:"scopes_supported"`
	} `json:"oauth_resource_metadata"`
	Dependencies struct {
		BridgeV1alpha1       map[string]string `json:"bridge_v1alpha1_schemas"`
		PlaceOrderFakeSchema string            `json:"bridge_v1alpha2_place_order_fake_schema"`
	} `json:"dependencies"`
}

var (
	once sync.Once
	doc  *Document
	derr error
)

// Load parses the embedded document once.
func Load() (*Document, error) {
	once.Do(func() {
		var d Document
		if err := json.Unmarshal(raw, &d); err != nil {
			derr = fmt.Errorf("glovojoin contract: %w", err)
			return
		}
		doc = &d
	})
	return doc, derr
}

// MustLoad is Load for the callers that cannot continue without the contract.
func MustLoad() *Document {
	d, err := Load()
	if err != nil {
		panic(err)
	}
	return d
}

// WireFor maps an internal glovo.Code (by name) to the HTTP status and the
// wire code of the facade routes. An unknown code is 503 dependency_unavailable:
// the set is closed and an unknown code fails closed.
func (d *Document) WireFor(code string) (status int, wire string) {
	for _, c := range d.Errors.Codes {
		if c.Code == code {
			return c.Status, c.Wire
		}
	}
	return 503, "dependency_unavailable"
}
