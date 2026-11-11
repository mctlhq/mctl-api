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

//go:build glovojoin_fixture

package glovo

// controlGateOpen backs ControlDefault in the fixture build (build tag
// glovojoin_fixture) so that mctl-api#990 can drive the real control routes.
// Opening it is the only thing the tag does: the fixture still has to satisfy
// every other fence precondition for real (design 7.4).
const controlGateOpen = true
