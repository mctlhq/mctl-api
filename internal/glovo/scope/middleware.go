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

package scope

import (
	"context"
	"net/http"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/glovo"
)

type ctxKey struct{}

// FromContext returns the Scope RequireScope resolved.
func FromContext(ctx context.Context) (Scope, bool) {
	s, ok := ctx.Value(ctxKey{}).(Scope)
	return s, ok
}

// RequireScope resolves the scope of every request before the handler runs,
// answering a refusal with the Glovo error body. It reads only the
// authenticated user from the context. A request with no user at all is the
// one 401.
func RequireScope(r *Resolver) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			u := auth.UserFromContext(req.Context())
			if u == nil {
				glovo.WriteUnauthenticated(w, "")
				return
			}
			sc, refusal := r.Resolve(req.Context(), u)
			if refusal != nil {
				glovo.WriteError(w, refusal)
				return
			}
			next.ServeHTTP(w, req.WithContext(context.WithValue(req.Context(), ctxKey{}, sc)))
		})
	}
}
