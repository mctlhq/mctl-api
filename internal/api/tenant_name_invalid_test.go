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

package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/gitops"
)

type invalidNameReader struct{ GitReader }

func (invalidNameReader) GetTenant(name string) (*gitops.Tenant, error) {
	return nil, fmt.Errorf("%w: %q", gitops.ErrInvalidTenantName, name)
}

// A name the reader refuses as invalid is a 400, distinct from a 404 for a
// missing tenant, on both read routes that pass a URL parameter to GetTenant
// (mctl-api#232).
func TestTenantReadRoutesAnswer400ForInvalidName(t *testing.T) {
	h := &Handlers{opts: Options{GitReader: &invalidNameReader{}}}
	admin := auth.NewGitHubUser("root", []string{"admins"})

	cases := map[string]struct {
		param string
		do    func(http.ResponseWriter, *http.Request)
	}{
		"tenant": {"name", h.GetTenant},
		"quota":  {"tenant", h.GetResourceUsage},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			req := withURLParam(withUser(httptest.NewRequest(http.MethodGet, "/x", nil), admin), c.param, "../x")
			w := httptest.NewRecorder()
			c.do(w, req)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", w.Code, w.Body.String())
			}
		})
	}
}
