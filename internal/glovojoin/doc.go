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

// Package glovojoin holds the facade-to-MCTL join of mctl-api#957. This file
// set is the schema slice only (task A14): the four join tables, their
// grants and the read of the workflow-start record. It has no route and no
// handler, and it must never import internal/glovo/control (the control
// package imports this one, never the reverse; #957 design 6d.1).
package glovojoin
