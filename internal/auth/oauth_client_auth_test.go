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

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/auth/cimd"
)

// A jti is accepted once across replicas sharing the flow store, per client.
func TestJTIIsSingleUseAcrossReplicas(t *testing.T) {
	a, b, _ := twoReplicas(t)
	ctx := context.Background()
	as := cimd.Assertion{JTI: "j1", RememberFor: time.Minute}
	if err := a.consumeJTI(ctx, "https://app.example.com/c.json", as); err != nil {
		t.Fatal(err)
	}
	if err := b.consumeJTI(ctx, "https://app.example.com/c.json", as); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("replay on the other replica: %v", err)
	}
	// The same jti from another client is that client's own.
	if err := b.consumeJTI(ctx, "https://app.example.com/other.json", as); err != nil {
		t.Fatal(err)
	}
}

// Without a shared store the replay check still holds within the process.
func TestJTIIsSingleUseInMemory(t *testing.T) {
	s := newTestOAuthServer(t)
	as := cimd.Assertion{JTI: "j1", RememberFor: time.Minute}
	if err := s.consumeJTI(context.Background(), "c", as); err != nil {
		t.Fatal(err)
	}
	if err := s.consumeJTI(context.Background(), "c", as); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("replay: %v", err)
	}
}

// A store that cannot record the jti is a server error, never a pass and
// never invalid_client.
func TestJTIStoreFailureIsServerError(t *testing.T) {
	s := newTestOAuthServer(t)
	st := newMemFlowStore()
	st.putErr = errors.New("db down")
	s.FlowStore = st
	err := s.consumeJTI(context.Background(), "c", cimd.Assertion{JTI: "j", RememberFor: time.Minute})
	if !errors.Is(err, ErrServerError) || errors.Is(err, ErrInvalidClient) {
		t.Fatalf("%v", err)
	}
}
