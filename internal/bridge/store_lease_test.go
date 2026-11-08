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

package bridge

import (
	"errors"
	"testing"
	"time"
)

func TestLeaseLivePrecedence(t *testing.T) {
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	s := &Store{now: func() time.Time { return now }}
	past := now.Add(-time.Minute)
	future := now.Add(time.Minute)
	pp, fp := &past, &future
	cases := []struct {
		name   string
		status string
		stored string
		lease  *time.Time
		exp    time.Time
		tok    string
		want   error
	}{
		{"valid", StatusLeased, "lt_a", fp, future, "lt_a", nil},
		{"wrong token", StatusLeased, "lt_a", fp, future, "lt_b", ErrLeaseStale},
		{"nil lease", StatusLeased, "lt_a", nil, future, "lt_a", ErrLeaseStale},
		{"lease elapsed command live", StatusLeased, "lt_a", pp, future, "lt_a", ErrLeaseStale},
		{"command elapsed lease live", StatusLeased, "lt_a", fp, past, "lt_a", ErrCommandExpired},
		{"both elapsed", StatusLeased, "lt_a", pp, past, "lt_a", ErrCommandExpired},
		{"nil lease command elapsed", StatusLeased, "lt_a", nil, past, "lt_a", ErrCommandExpired},
		{"wrong token command elapsed", StatusLeased, "lt_a", pp, past, "lt_b", ErrLeaseStale},
		{"stored expired", StatusExpired, "lt_a", fp, future, "lt_a", ErrCommandExpired},
		{"cancelled", StatusCancelled, "lt_a", fp, future, "lt_a", ErrCommandCancelled},
		{"pending", StatusPending, "", nil, future, "lt_a", ErrLeaseStale},
		{"completed", StatusCompleted, "lt_a", fp, future, "lt_a", ErrLeaseStale},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			row := &cmdRow{Status: c.status, LeaseToken: c.stored, LeaseExpiresAt: c.lease, ExpiresAt: c.exp}
			if got := s.leaseLive(row, c.tok); !errors.Is(got, c.want) {
				t.Fatalf("got %v, want %v", got, c.want)
			}
		})
	}
}
