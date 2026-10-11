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

package operations

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

// Secret parameter handoff.
//
// A Workflow's spec.arguments.parameters is plain data on the Workflow
// object: it stays readable for as long as the object lives (the TTL keeps
// finished Workflows for 30 minutes after success and days after failure)
// by anyone who may read Workflows in that namespace, and it is rendered
// into the pods that consume it. The `Secret` flag on a ParameterDef only
// redacts mctl-api's own logs. So a value flagged Secret never goes into
// the Workflow spec. Instead:
//
//  1. the Workflow is created suspended, with each secret parameter
//     replaced by a value-free projection (for secret_env_vars: the key
//     names, which the gitops commit step needs to wire the ExternalSecret)
//     and SecretHandoffParam naming a Kubernetes Secret;
//  2. that Secret is created in the Workflow's namespace, owned by the
//     Workflow, so it is garbage-collected together with it;
//  3. the Workflow is resumed. The template mounts the Secret and writes
//     the values to Vault without ever placing them in a parameter.
//
// Every step fails closed: if the template does not declare
// SecretHandoffParam, nothing is submitted; if the Secret cannot be created
// or the Workflow cannot be resumed, the Workflow is terminated before any
// step has run and the caller gets an error.

// SecretHandoffParam is the workflow parameter that names the Kubernetes
// Secret carrying the values of an operation's secret parameters. Each value
// is stored under the parameter's own name as the Secret data key.
const SecretHandoffParam = "secret_env_secret"

// ClearSentinel is the env_vars / secret_env_vars value that tells the
// deploy-service template to clear the existing values. It is an
// instruction, not a secret, and travels as-is. The MCP layer sends it.
const ClearSentinel = "__CLEAR__"

var (
	secretGVR = schema.GroupVersionResource{Version: "v1", Resource: "secrets"}

	clusterWorkflowTemplateGVR = schema.GroupVersionResource{
		Group:    "argoproj.io",
		Version:  "v1alpha1",
		Resource: "clusterworkflowtemplates",
	}

	envVarName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// secretProjections maps a secret parameter to the value-free form that
// replaces it in the Workflow spec. A secret parameter without an entry
// cannot be submitted with a value: refusing is the only answer that does
// not either leak the value or silently drop it.
var secretProjections = map[string]func(string) (string, error){
	"secret_env_vars": secretEnvKeyNames,
}

// secretEnvKeyNames returns the key names of newline-separated KEY=value
// lines, one per line, parsed the way the deploy-service template parses
// them: blank lines and lines whose key starts with '#' are skipped, and
// keys are trimmed. Every other line must contain '=' and a key that is an
// environment variable name (the template refuses other keys too).
//
// The projection is published on the Workflow, so it must never carry a
// value. A line without '=' is refused because it can only be a value: a
// stray token, or a continuation line of a multi-line value such as a PEM
// block. A continuation line that itself looks like KEY=... cannot be told
// apart from a real pair, and its prefix is published as a key name.
func secretEnvKeyNames(value string) (string, error) {
	var keys []string
	for i, line := range strings.Split(value, "\n") {
		key, _, found := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if key == "" || strings.HasPrefix(key, "#") {
			continue
		}
		if !found {
			return "", fmt.Errorf("secret_env_vars line %d: not a KEY=value line (multi-line values are not supported)", i+1)
		}
		if !envVarName.MatchString(key) {
			return "", fmt.Errorf("secret_env_vars line %d: key is not a valid environment variable name", i+1)
		}
		keys = append(keys, key)
	}
	return strings.Join(keys, "\n"), nil
}

// splitSecretParams separates the values of op's secret parameters from the
// parameters that may go into the Workflow spec. It returns the parameters
// to submit (secret values replaced by their projection) and the secret
// values to hand off. Empty values and the clear sentinel carry nothing
// secret and are left in place. A caller-supplied SecretHandoffParam is
// always discarded: only Submit may name the handoff Secret.
func splitSecretParams(op Operation, params map[string]string) (map[string]string, map[string]string, error) {
	public := make(map[string]string, len(params))
	for k, v := range params {
		if k == SecretHandoffParam {
			continue
		}
		public[k] = v
	}
	var secrets map[string]string
	for _, p := range op.Parameters {
		if !p.Secret {
			continue
		}
		v, ok := params[p.Name]
		if !ok || v == "" || v == ClearSentinel {
			continue
		}
		project, ok := secretProjections[p.Name]
		if !ok {
			return nil, nil, fmt.Errorf("operation %s: secret parameter %s has no handoff projection; refusing to submit its value", op.Name, p.Name)
		}
		projected, err := project(v)
		if err != nil {
			return nil, nil, err
		}
		if projected == "" {
			// Only blank or comment lines: nothing to store, and nothing
			// worth handing to the template, which would refuse an empty
			// Secret. Submitted as no secrets at all.
			public[p.Name] = ""
			continue
		}
		if secrets == nil {
			secrets = map[string]string{}
		}
		secrets[p.Name] = v
		public[p.Name] = projected
	}
	return public, secrets, nil
}

// handoffSecretName is the name of the Secret that carries workflowName's
// secret parameter values.
func handoffSecretName(workflowName string) string {
	return workflowName + "-secret-env"
}

// checkSecretHandoffSupport refuses to hand secrets to a template that does
// not declare SecretHandoffParam. A template that predates the handoff would
// read the value-free projection as the secret values themselves. A failed
// read is a refusal too: "could not check" is not "supported".
func (e *Executor) checkSecretHandoffSupport(ctx context.Context, template string) error {
	cwt, err := e.dynamicClient.Resource(clusterWorkflowTemplateGVR).Get(ctx, template, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("check template %s for secret handoff support: %w", template, err)
	}
	params, _, err := unstructured.NestedSlice(cwt.Object, "spec", "arguments", "parameters")
	if err != nil {
		return fmt.Errorf("check template %s for secret handoff support: %w", template, err)
	}
	for _, p := range params {
		if m, ok := p.(map[string]interface{}); ok && m["name"] == SecretHandoffParam {
			return nil
		}
	}
	return fmt.Errorf("template %s does not declare parameter %s; refusing to submit secret values", template, SecretHandoffParam)
}

// createHandoffSecret stores the secret values in a Secret owned by wf.
func (e *Executor) createHandoffSecret(ctx context.Context, wf *unstructured.Unstructured, name string, values map[string]string, labels map[string]string) error {
	if wf.GetUID() == "" {
		return fmt.Errorf("workflow %s has no uid; cannot own secret %s", wf.GetName(), name)
	}
	data := make(map[string]interface{}, len(values))
	for k, v := range values {
		data[k] = v
	}
	secretLabels := make(map[string]interface{}, len(labels)+1)
	for k, v := range labels {
		secretLabels[k] = v
	}
	secretLabels["app.kubernetes.io/managed-by"] = "mctl-api"
	secret := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata": map[string]interface{}{
			"name":      name,
			"namespace": wf.GetNamespace(),
			"labels":    secretLabels,
			// Owned, not controlled: deleting the Workflow (its TTL) deletes
			// the Secret. blockOwnerDeletion stays unset so no permission on
			// the Workflow's finalizers is needed.
			"ownerReferences": []interface{}{map[string]interface{}{
				"apiVersion": "argoproj.io/v1alpha1",
				"kind":       "Workflow",
				"name":       wf.GetName(),
				"uid":        string(wf.GetUID()),
			}},
		},
		"type":       "Opaque",
		"immutable":  true,
		"stringData": data,
	}}
	_, err := e.dynamicClient.Resource(secretGVR).Namespace(wf.GetNamespace()).Create(ctx, secret, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("create secret %s: %w", name, err)
	}
	return nil
}

// resumeWorkflow clears the suspension Submit created the Workflow with.
func (e *Executor) resumeWorkflow(ctx context.Context, namespace, name string) error {
	_, err := e.dynamicClient.Resource(workflowGVR).Namespace(namespace).Patch(ctx, name,
		types.MergePatchType, []byte(`{"spec":{"suspend":null}}`), metav1.PatchOptions{})
	if err != nil {
		return fmt.Errorf("resume workflow %s: %w", name, err)
	}
	return nil
}

// abortWorkflow terminates a Workflow whose secret handoff failed. Suspend
// is cleared in the same patch because Argo does not act on a shutdown
// request while the Workflow is suspended. Nothing has run yet, so the
// Workflow fails without executing a step. Best effort: the caller is
// already returning an error, and a Workflow left suspended runs nothing.
// The request context may already be cancelled (that can be why the handoff
// failed), so the patch runs on a detached context with its own deadline.
func (e *Executor) abortWorkflow(ctx context.Context, namespace, name string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	_, err := e.dynamicClient.Resource(workflowGVR).Namespace(namespace).Patch(ctx, name,
		types.MergePatchType, []byte(`{"spec":{"suspend":null,"shutdown":"Terminate"}}`), metav1.PatchOptions{})
	if err != nil {
		slog.Error("could not terminate workflow after failed secret handoff; it stays suspended",
			"workflow", name, "namespace", namespace, "error", err)
	}
}
