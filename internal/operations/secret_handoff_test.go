// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package operations

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

const (
	handoffValueA = "s3cr3t-value-alpha"
	handoffValueB = "p@ss=with=equals"
)

func handoffSecretEnv() string {
	return "# comment line\nAPI_KEY=" + handoffValueA + "\n\n  DB_PASSWORD = " + handoffValueB + "\n"
}

func deployServiceOp(t *testing.T) Operation {
	t.Helper()
	op, ok := NewRegistry().Get("deploy-service")
	if !ok {
		t.Fatal("deploy-service is not registered")
	}
	return op
}

// handoffCluster is a fake cluster holding the deploy-service
// ClusterWorkflowTemplate. It records every Workflow as it was created and
// gives created Workflows a uid, as the API server does.
type handoffCluster struct {
	dyn     *dynamicfake.FakeDynamicClient
	created []*unstructured.Unstructured
}

func newHandoffCluster(t *testing.T, templateParams ...string) *handoffCluster {
	t.Helper()
	params := make([]interface{}, 0, len(templateParams))
	for _, p := range templateParams {
		params = append(params, map[string]interface{}{"name": p})
	}
	cwt := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "argoproj.io/v1alpha1",
		"kind":       "ClusterWorkflowTemplate",
		"metadata":   map[string]interface{}{"name": "deploy-service"},
		"spec": map[string]interface{}{
			"arguments": map[string]interface{}{"parameters": params},
		},
	}}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{
			workflowGVR:                "WorkflowList",
			secretGVR:                  "SecretList",
			clusterWorkflowTemplateGVR: "ClusterWorkflowTemplateList",
		}, cwt)
	c := &handoffCluster{dyn: dyn}
	dyn.PrependReactor("create", "workflows", func(action k8stesting.Action) (bool, runtime.Object, error) {
		obj := action.(k8stesting.CreateAction).GetObject().(*unstructured.Unstructured)
		obj.SetUID(types.UID("uid-" + obj.GetName()))
		c.created = append(c.created, obj.DeepCopy())
		return false, nil, nil
	})
	return c
}

func (c *handoffCluster) workflow(t *testing.T, ns, name string) *unstructured.Unstructured {
	t.Helper()
	wf, err := c.dyn.Resource(workflowGVR).Namespace(ns).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return wf
}

func workflowParam(t *testing.T, wf *unstructured.Unstructured, name string) (string, bool) {
	t.Helper()
	params, _, _ := unstructured.NestedSlice(wf.Object, "spec", "arguments", "parameters")
	for _, p := range params {
		m := p.(map[string]interface{})
		if m["name"] == name {
			v, _ := m["value"].(string)
			return v, true
		}
	}
	return "", false
}

func assertNoSecretValue(t *testing.T, what string, obj *unstructured.Unstructured) {
	t.Helper()
	raw, err := json.Marshal(obj.Object)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{handoffValueA, handoffValueB} {
		if strings.Contains(string(raw), v) {
			t.Errorf("%s contains a secret value: %s", what, raw)
		}
	}
}

// The values of secret_env_vars must not appear anywhere in the Workflow,
// neither as submitted nor as it stands afterwards. They travel in a Secret
// owned by the Workflow, and the Workflow only learns the key names.
func TestSubmitKeepsSecretValuesOutOfTheWorkflow(t *testing.T) {
	c := newHandoffCluster(t, "action", "secret_env_vars", SecretHandoffParam)
	e := &Executor{dynamicClient: c.dyn}
	params := map[string]string{
		"action":          "deploy",
		"team_name":       "labs",
		"component_name":  "web",
		"secret_env_vars": handoffSecretEnv(),
		// A caller cannot pick the Secret the template reads.
		SecretHandoffParam: "someone-elses-secret",
	}

	res, err := e.Submit(context.Background(), deployServiceOp(t), params, "u", "labs")
	if err != nil {
		t.Fatal(err)
	}

	if len(c.created) != 1 {
		t.Fatalf("created %d workflows, want 1", len(c.created))
	}
	submitted := c.created[0]
	assertNoSecretValue(t, "submitted workflow", submitted)
	if s, _, _ := unstructured.NestedBool(submitted.Object, "spec", "suspend"); !s {
		t.Error("workflow was not created suspended")
	}

	wf := c.workflow(t, res.Namespace, res.WorkflowName)
	assertNoSecretValue(t, "stored workflow", wf)
	if _, found, _ := unstructured.NestedFieldNoCopy(wf.Object, "spec", "suspend"); found {
		t.Error("workflow was not resumed after the handoff")
	}
	if got, _ := workflowParam(t, wf, "secret_env_vars"); got != "API_KEY\nDB_PASSWORD" {
		t.Errorf("secret_env_vars parameter = %q, want the key names only", got)
	}
	secretName, _ := workflowParam(t, wf, SecretHandoffParam)
	if secretName != res.WorkflowName+"-secret-env" {
		t.Fatalf("%s = %q", SecretHandoffParam, secretName)
	}

	secret, err := c.dyn.Resource(secretGVR).Namespace(res.Namespace).Get(context.Background(), secretName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got, _, _ := unstructured.NestedString(secret.Object, "stringData", "secret_env_vars"); got != handoffSecretEnv() {
		t.Errorf("secret data = %q, want the caller's value unchanged", got)
	}
	if imm, _, _ := unstructured.NestedBool(secret.Object, "immutable"); !imm {
		t.Error("secret is not immutable")
	}
	owners := secret.GetOwnerReferences()
	if len(owners) != 1 || owners[0].Kind != "Workflow" || owners[0].Name != res.WorkflowName || owners[0].UID != wf.GetUID() {
		t.Errorf("secret owner references = %+v, want the workflow", owners)
	}
}

// Nothing secret to hand off: no Secret, no suspension, and the clear
// sentinel reaches the template as before.
func TestSubmitWithoutSecretValuesIsUnchanged(t *testing.T) {
	for _, value := range []string{"", clearSentinel} {
		c := newHandoffCluster(t, "action")
		e := &Executor{dynamicClient: c.dyn}
		params := map[string]string{"action": "update-config", "secret_env_vars": value, SecretHandoffParam: "someone-elses-secret"}
		res, err := e.Submit(context.Background(), deployServiceOp(t), params, "u", "labs")
		if err != nil {
			t.Fatalf("%q: %v", value, err)
		}
		wf := c.workflow(t, res.Namespace, res.WorkflowName)
		if _, found, _ := unstructured.NestedFieldNoCopy(c.created[0].Object, "spec", "suspend"); found {
			t.Errorf("%q: workflow created suspended", value)
		}
		if got, _ := workflowParam(t, wf, "secret_env_vars"); got != value {
			t.Errorf("%q: secret_env_vars = %q", value, got)
		}
		if _, ok := workflowParam(t, wf, SecretHandoffParam); ok {
			t.Errorf("%q: %s set without a secret", value, SecretHandoffParam)
		}
		list, err := c.dyn.Resource(secretGVR).Namespace(res.Namespace).List(context.Background(), metav1.ListOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if len(list.Items) != 0 {
			t.Errorf("%q: %d secrets created", value, len(list.Items))
		}
	}
}

// A template that does not declare the handoff parameter would treat the key
// names as the secret values. Nothing may be submitted to it, and a template
// that cannot be read is no better.
func TestSubmitRefusesTemplateWithoutHandoffSupport(t *testing.T) {
	c := newHandoffCluster(t, "action", "secret_env_vars")
	e := &Executor{dynamicClient: c.dyn}
	params := map[string]string{"action": "deploy", "secret_env_vars": handoffSecretEnv()}
	if _, err := e.Submit(context.Background(), deployServiceOp(t), params, "u", "labs"); err == nil {
		t.Fatal("submitted to a template without handoff support")
	}
	if len(c.created) != 0 {
		t.Errorf("created %d workflows", len(c.created))
	}

	c = newHandoffCluster(t, "action", "secret_env_vars", SecretHandoffParam)
	c.dyn.PrependReactor("get", "clusterworkflowtemplates", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("apiserver unavailable")
	})
	e = &Executor{dynamicClient: c.dyn}
	if _, err := e.Submit(context.Background(), deployServiceOp(t), params, "u", "labs"); err == nil {
		t.Fatal("submitted although the template could not be read")
	}
	if len(c.created) != 0 {
		t.Errorf("created %d workflows", len(c.created))
	}
}

// When the handoff fails after the Workflow exists, the Workflow must be
// terminated before it runs a step, and the caller must get an error that
// does not carry the secret values.
func TestSubmitTerminatesWorkflowWhenHandoffFails(t *testing.T) {
	for _, tc := range []struct {
		name  string
		verb  string
		res   string
		patch int // patch call that fails, 1-based; 0 = none
	}{
		{name: "secret create fails", verb: "create", res: "secrets"},
		{name: "resume fails", verb: "patch", res: "workflows", patch: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newHandoffCluster(t, "action", "secret_env_vars", SecretHandoffParam)
			patches := 0
			c.dyn.PrependReactor(tc.verb, tc.res, func(k8stesting.Action) (bool, runtime.Object, error) {
				if tc.verb == "patch" {
					patches++
					if patches != tc.patch {
						return false, nil, nil
					}
				}
				return true, nil, errors.New("forbidden")
			})
			var lastPatch string
			c.dyn.PrependReactor("patch", "workflows", func(a k8stesting.Action) (bool, runtime.Object, error) {
				lastPatch = string(a.(k8stesting.PatchAction).GetPatch())
				return false, nil, nil
			})
			e := &Executor{dynamicClient: c.dyn}
			params := map[string]string{"action": "deploy", "secret_env_vars": handoffSecretEnv()}

			_, err := e.Submit(context.Background(), deployServiceOp(t), params, "u", "labs")
			if err == nil {
				t.Fatal("Submit succeeded although the handoff failed")
			}
			for _, v := range []string{handoffValueA, handoffValueB} {
				if strings.Contains(err.Error(), v) {
					t.Errorf("error carries a secret value: %v", err)
				}
			}
			if len(c.created) != 1 {
				t.Fatalf("created %d workflows, want 1", len(c.created))
			}
			wf := c.workflow(t, "labs", c.created[0].GetName())
			if got, _, _ := unstructured.NestedString(wf.Object, "spec", "shutdown"); got != "Terminate" {
				t.Errorf("workflow shutdown = %q, want Terminate (last patch %s)", got, lastPatch)
			}
			if _, found, _ := unstructured.NestedFieldNoCopy(wf.Object, "spec", "suspend"); found {
				t.Error("terminated workflow is still suspended; Argo ignores shutdown while suspended")
			}
		})
	}
}

func TestSecretEnvKeyNames(t *testing.T) {
	got, err := secretEnvKeyNames("A=1\r\n#B=2\n  # C=3\n\nD_E = x=y\n")
	if err != nil {
		t.Fatal(err)
	}
	if got != "A\nD_E" {
		t.Errorf("key names = %q", got)
	}
	// A line without '=' may be a stray value: refused, and not echoed.
	_, err = secretEnvKeyNames("A=1\n" + handoffValueA + "-no-equals!")
	if err == nil {
		t.Fatal("invalid key accepted")
	}
	if strings.Contains(err.Error(), handoffValueA) {
		t.Errorf("error echoes the line: %v", err)
	}
}

// A secret parameter without a projection cannot be submitted with a value.
func TestSplitSecretParamsRefusesUnprojectedSecret(t *testing.T) {
	op := Operation{Name: "x", Parameters: []ParameterDef{{Name: "token", Secret: true}}}
	if _, _, err := splitSecretParams(op, map[string]string{"token": "v"}); err == nil {
		t.Fatal("unprojected secret parameter accepted")
	}
	if _, secrets, err := splitSecretParams(op, map[string]string{"token": ""}); err != nil || secrets != nil {
		t.Fatalf("empty secret parameter: secrets=%v err=%v", secrets, err)
	}
}

// Comment-only input carries no key: nothing is handed off, and the
// comment text does not reach the Workflow either.
func TestSplitSecretParamsCommentOnly(t *testing.T) {
	op := Operation{Name: "x", Parameters: []ParameterDef{{Name: "secret_env_vars", Secret: true}}}
	public, secrets, err := splitSecretParams(op, map[string]string{"secret_env_vars": "# " + handoffValueA + "\n\n"})
	if err != nil {
		t.Fatal(err)
	}
	if secrets != nil {
		t.Errorf("secrets = %v, want none", secrets)
	}
	if got := public["secret_env_vars"]; got != "" {
		t.Errorf("secret_env_vars = %q, want empty", got)
	}
}
