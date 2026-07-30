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

package argoarchive

import (
	"context"
	"os"
	"testing"
)

// TestIntegrationAgainstLiveArchive exercises the signer against the real
// object store. Unit tests can only prove the signature matches AWS's
// published vectors; only a live call proves the endpoint accepts it.
//
// Opt-in — skipped unless credentials are exported:
//
//	eval "$(VAULT_ADDR=https://secrets.mctl.ai vault kv get -format=json \
//	  secret/platform/r2-loki-argo | jq -r '.data.data |
//	  "export ARGO_LOGS_R2_ENDPOINT=\(.["account-id"]).r2.cloudflarestorage.com
//	   export ARGO_LOGS_R2_ACCESS_KEY=\(.["access-key"])
//	   export ARGO_LOGS_R2_SECRET_KEY=\(.["secret-key"])"')"
//	export ARGO_LOGS_R2_BUCKET=argo-workflows-logs
//	export ARGO_LOGS_TEST_WORKFLOW=<a workflow name inside the 30d window>
//	go test ./internal/argoarchive/ -run Integration -v
func TestIntegrationAgainstLiveArchive(t *testing.T) {
	endpoint := os.Getenv("ARGO_LOGS_R2_ENDPOINT")
	bucket := os.Getenv("ARGO_LOGS_R2_BUCKET")
	accessKey := os.Getenv("ARGO_LOGS_R2_ACCESS_KEY")
	secretKey := os.Getenv("ARGO_LOGS_R2_SECRET_KEY")
	workflow := os.Getenv("ARGO_LOGS_TEST_WORKFLOW")

	if endpoint == "" || bucket == "" || accessKey == "" || secretKey == "" || workflow == "" {
		t.Skip("live archive credentials not exported; see the doc comment")
	}

	c := NewClient(endpoint, bucket, accessKey, secretKey)
	ctx := context.Background()

	steps, err := c.ListSteps(ctx, workflow)
	if err != nil {
		t.Fatalf("ListSteps against live archive: %v", err)
	}
	if len(steps) == 0 {
		t.Fatalf("no archived steps for %q — pick a workflow inside the bucket's retention window", workflow)
	}
	for _, s := range steps {
		t.Logf("step=%s size=%d key=%s", s.Step, s.Size, s.Key)
	}

	body, err := c.GetStep(ctx, steps[len(steps)-1].Key, 20)
	if err != nil {
		t.Fatalf("GetStep against live archive: %v", err)
	}
	if body == "" {
		t.Error("live step log came back empty")
	}
	t.Logf("tail of %s:\n%s", steps[len(steps)-1].Step, body)
}
