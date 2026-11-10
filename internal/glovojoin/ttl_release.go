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

package glovojoin

import "time"

// GlovoApprovalTTL is the life of the approval a prepare creates (mctl-api#957
// design 6, OPEN-957-10 default). It is a constant of the release build: the
// only way to move it is the glovojoin_fixture tag, which nothing that ships
// passes. The approval is also capped at the aar_ fresh_until by the work-item
// store.
const GlovoApprovalTTL = 15 * time.Minute
