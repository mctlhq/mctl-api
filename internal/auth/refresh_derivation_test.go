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

package auth

import "testing"

func TestDeriveSuccessorRefreshToken_Deterministic(t *testing.T) {
	secret := []byte("test-secret")
	a := deriveSuccessorRefreshToken(secret, "predecessor-1")
	b := deriveSuccessorRefreshToken(secret, "predecessor-1")
	if a != b {
		t.Errorf("derivation is not deterministic: %q != %q", a, b)
	}
}

func TestDeriveSuccessorRefreshToken_DifferentPredecessorDiffers(t *testing.T) {
	secret := []byte("test-secret")
	a := deriveSuccessorRefreshToken(secret, "predecessor-1")
	b := deriveSuccessorRefreshToken(secret, "predecessor-2")
	if a == b {
		t.Error("different predecessors produced the same successor")
	}
}

func TestDeriveSuccessorRefreshToken_DifferentSecretDiffers(t *testing.T) {
	predecessor := "predecessor-1"
	a := deriveSuccessorRefreshToken([]byte("secret-a"), predecessor)
	b := deriveSuccessorRefreshToken([]byte("secret-b"), predecessor)
	if a == b {
		t.Error("different secrets produced the same successor")
	}
}

func TestDeriveSuccessorRefreshToken_NonEmpty(t *testing.T) {
	got := deriveSuccessorRefreshToken([]byte("secret"), "predecessor")
	if got == "" {
		t.Error("derived successor is empty")
	}
}
