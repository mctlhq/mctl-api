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

package gitops

import _ "embed"

// githubKnownHosts holds GitHub's published SSH host key lines for
// github.com (RSA, ECDSA, ED25519), in standard known_hosts format. It is
// the fail-closed default used by the SSH branch of Reader.refresh() when
// no explicit knownHostsPath override is configured. Source: GitHub's
// documented SSH key fingerprints
// (https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints)
// and https://api.github.com/meta.
//
//go:embed github_known_hosts
var githubKnownHosts []byte
