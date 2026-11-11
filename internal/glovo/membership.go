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

package glovo

import (
	"context"
	"errors"
	"time"
)

// MembershipTimeout is the hard bound on one live membership read taken while
// row locks are held (mctl-api#985 and #989). It is shorter than the 5 s
// lock_timeout of the control transactions, so a hung provider cannot keep an
// order or approval row locked past it.
const MembershipTimeout = 2 * time.Second

// ErrMembershipTimeout is returned when the membership read did not answer in
// time. It is an unobserved answer, never "not a member".
var ErrMembershipTimeout = errors.New("glovo: membership read timed out")

// BoundedMembership runs read in its own goroutine and gives up after timeout
// (MembershipTimeout when zero) or when ctx ends, whichever is first. The
// provider call may be unable to honor a context, so the wait is bounded here
// and the abandoned goroutine ends whenever the provider does. A timeout is an
// error, so the callers answer unavailable and never infer absence.
func BoundedMembership(ctx context.Context, timeout time.Duration, read func(ctx context.Context) (bool, error)) (bool, error) {
	if timeout <= 0 {
		timeout = MembershipTimeout
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	type answer struct {
		member bool
		err    error
	}
	ch := make(chan answer, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				ch <- answer{err: errors.New("glovo: membership read panicked")}
			}
		}()
		m, err := read(cctx)
		ch <- answer{m, err}
	}()
	select {
	case a := <-ch:
		return a.member, a.err
	case <-cctx.Done():
		return false, ErrMembershipTimeout
	}
}
