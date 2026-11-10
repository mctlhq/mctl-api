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

//go:build !glovojoin_fixture

package control

import "time"

// DispatchCommandTTL is the life of a dispatched command (OPEN-985-13): the
// #1059 ttl_seconds maximum, equal to #1044's settle_timeout_s default, so the
// workflow never gives up on a command that is still live. The effective value
// is always capped at the time left until the aar_ fresh_until.
const DispatchCommandTTL = 900 * time.Second
