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

package live

import (
	"context"
	"net/http"
	"net/http/httptest"
)

// GuardRefuses reports whether the host guard built for cfg refuses a
// request to rawURL.
func GuardRefuses(cfg Config, rawURL string) bool {
	c, err := newCore(cfg, nopTokens{})
	if err != nil {
		return false
	}
	req := httptest.NewRequest(http.MethodGet, rawURL, nil)
	resp, err := c.hc.Transport.RoundTrip(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	return err == ErrHostNotAllowed
}

type nopTokens struct{}

func (nopTokens) Token(context.Context) (string, error)   { return "t", nil }
func (nopTokens) Refresh(context.Context) (string, error) { return "t", nil }
