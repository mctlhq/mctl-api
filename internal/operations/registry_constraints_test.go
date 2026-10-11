package operations

import (
	"regexp"
	"strings"
	"testing"
)

var anchoredRe = regexp.MustCompile(`^(\(\?[a-z]+\))?\^`)

func isConstrained(p ParameterDef) bool {
	if len(p.Enum) > 0 {
		return true
	}
	return p.Pattern != "" && anchoredRe.MatchString(p.Pattern) && strings.HasSuffix(p.Pattern, "$")
}

// constraintViolations reports unconstrained parameters and stale map entries.
func constraintViolations(ops []Operation, free, exempt map[string]map[string]string) []string {
	var out []string
	index := map[string]map[string]ParameterDef{}
	for _, op := range ops {
		if op.WorkflowTemplate == "" {
			continue
		}
		index[op.Name] = map[string]ParameterDef{}
		for _, p := range op.Parameters {
			index[op.Name][p.Name] = p
			if _, ok := exempt[op.Name][p.Name]; ok {
				continue
			}
			if !isConstrained(p) {
				out = append(out, op.Name+"/"+p.Name+": unconstrained")
			}
		}
	}
	check := func(label string, m map[string]map[string]string, needMax bool) {
		for o, ps := range m {
			for n := range ps {
				p, ok := index[o][n]
				if !ok {
					out = append(out, o+"/"+n+": stale "+label+" entry")
					continue
				}
				if needMax && p.MaxLength <= 0 {
					out = append(out, o+"/"+n+": "+label+" without MaxLength")
				}
			}
		}
	}
	check("free-text", free, true)
	check("exemption", exempt, false)
	return out
}

func TestEveryWorkflowParameterIsConstrained(t *testing.T) {
	if v := constraintViolations(builtinOperations, freeTextParameters, unconstrainedParameters); len(v) > 0 {
		t.Fatalf("violations: %v", v)
	}
	for o, ps := range unconstrainedParameters {
		for n := range ps {
			for _, op := range builtinOperations {
				for _, p := range op.Parameters {
					if op.Name == o && p.Name == n && p.MaxLength <= 0 {
						t.Errorf("%s/%s exempt without MaxLength", o, n)
					}
				}
			}
		}
	}
}

func TestConstraintCheckFailsWhenAnyConstraintIsRemoved(t *testing.T) {
	for i, op := range builtinOperations {
		for j, p := range op.Parameters {
			if _, ok := unconstrainedParameters[op.Name][p.Name]; ok {
				continue
			}
			ops := make([]Operation, len(builtinOperations))
			copy(ops, builtinOperations)
			params := make([]ParameterDef, len(op.Parameters))
			copy(params, op.Parameters)
			params[j].Enum, params[j].Pattern = nil, ""
			ops[i].Parameters = params
			v := constraintViolations(ops, freeTextParameters, unconstrainedParameters)
			if len(v) != 1 || !strings.HasPrefix(v[0], op.Name+"/"+p.Name+":") {
				t.Errorf("%s/%s: got %v", op.Name, p.Name, v)
			}
		}
	}
}

func TestConstraintCheckReportsSyntheticAndUnanchored(t *testing.T) {
	ops := []Operation{{Name: "x", WorkflowTemplate: "x", Parameters: []ParameterDef{
		{Name: "bare"}, {Name: "loose", Pattern: `[a-z]+`}, {Name: "ok", Pattern: `(?s)^a$`},
	}}}
	v := constraintViolations(ops, nil, nil)
	if len(v) != 2 {
		t.Fatalf("got %v", v)
	}
}

func TestFreeTextAndExemptionListsHaveNoStaleEntries(t *testing.T) {
	stale := map[string]map[string]string{"nope": {"x": "y"}}
	if v := constraintViolations(builtinOperations, stale, unconstrainedParameters); len(v) != 1 {
		t.Fatalf("stale entry not reported: %v", v)
	}
	for o, ps := range freeTextParameters {
		for n := range ps {
			for _, op := range builtinOperations {
				for _, p := range op.Parameters {
					if op.Name == o && p.Name == n && !strings.Contains(p.Description, "via env only") {
						t.Errorf("%s/%s description lacks free-text note", o, n)
					}
				}
			}
		}
	}
}

func TestEveryParameterPatternCompiles(t *testing.T) {
	for _, op := range builtinOperations {
		for _, p := range op.Parameters {
			if p.Pattern == "" {
				continue
			}
			if _, err := regexp.Compile(p.Pattern); err != nil {
				t.Errorf("%s/%s: %v", op.Name, p.Name, err)
			}
		}
	}
}

func opByName(t *testing.T, name string) Operation {
	for _, op := range builtinOperations {
		if op.Name == name {
			return op
		}
	}
	t.Fatalf("no op %s", name)
	return Operation{}
}

func TestOperationParametersAcceptCurrentRealValues(t *testing.T) {
	r := &Registry{}
	cases := []struct {
		op string
		in map[string]string
	}{
		{"deploy-service", map[string]string{"action": "deploy", "team_name": "a", "component_name": "b", "host": "none", "env_vars": "__CLEAR__", "image_tag": "auto", "git_tag": "1.73.0", "dockerfile_repo": "mctlhq/mctl-api"}},
		{"deploy-service", map[string]string{"action": "deploy", "team_name": "a", "component_name": "b", "host": "app.example.com", "image_tag": "main-9c35416", "health_check_path": "/readyz", "service_template": "spring-worker", "env_vars": "A=b c \"$x\"\n\nB=1"}},
		{"deploy-service", map[string]string{"action": "deploy", "team_name": "a", "component_name": "b", "image_tag": "98c8352c1636"}},
		{"deploy-service", map[string]string{"action": "deploy", "team_name": "a", "component_name": "b", "dockerfile_path": "docker/api/Dockerfile.prod"}},
		{"preview-deploy", map[string]string{"team_name": "a", "component_name": "b", "image_tag": GeneratePreviewTag("main"), "dockerfile_path": "services/web_app/Dockerfile"}},
		{"create-tenant", map[string]string{"tenant_name": "abc", "quota_cpu_req": "500m", "quota_cpu_lim": "2", "quota_memory_req": "1500Mi", "quota_memory_lim": "5Gi", "quota_pods": "30", "creator_user_id": "octocat"}},
		{"preview-deploy", map[string]string{"team_name": "a", "component_name": "b", "image_tag": GeneratePreviewTag("feat/my-feature")}},
		{"mctl-agents-implement", map[string]string{"slug": "go-chi-v5.3.2-router-upgrade"}},
		{"mctl-agents-approve", map[string]string{"service": "mctl-api", "slug": "issue-559-hardening-constrain-every-operation-para", "approver": "agent:implementer"}},
	}
	for _, c := range cases {
		op := opByName(t, c.op)
		in := r.ApplyDefaults(op, c.in)
		if errs := r.ValidateInput(op, in); len(errs) > 0 {
			t.Errorf("%s %v: %v", c.op, c.in, errs)
		}
	}
}

func TestOperationParametersRejectInjectionShapes(t *testing.T) {
	r := &Registry{}
	long := strings.Repeat("a", 1025)
	cases := []struct{ op, k, v string }{
		{"deploy-service", "git_tag", "v1\nx"},
		{"deploy-service", "image_tag", "a\nb"},
		{"rollback-service", "target_tag", "a\nb"},
		{"deploy-service", "service_template", "../x"},
		{"deploy-service", "host", "$(id)"},
		{"add-custom-domain", "domain", "a.com;id"},
		{"deploy-service", "env_vars", "A=b\r\nC=d"},
		{"deploy-service", "env_vars", "A=b\x00"},
		{"create-tenant", "display_name", `a"b`},
		{"create-tenant", "description", long},
		{"deploy-service", "port", "80a"},
		{"preview-deploy", "ttl_hours", "x"},
		{"deploy-service", "min_replicas", "x"},
		{"platform-skill-publish", "content_b64", "not base64!"},
		{"deploy-service", "dockerfile_path", "a/../../../etc/passwd"},
		{"deploy-service", "dockerfile_path", "a/./Dockerfile"},
		{"deploy-service", "dockerfile_path", "a//Dockerfile"},
		{"deploy-service", "dockerfile_path", "/etc/passwd"},
		{"deploy-service", "dockerfile_path", "-f"},
		{"deploy-service", "dockerfile_path", strings.Repeat("a", 257)},
		{"preview-deploy", "dockerfile_path", "x/.."},
	}
	for _, c := range cases {
		op := opByName(t, c.op)
		errs := r.ValidateInput(op, map[string]string{c.k: c.v})
		found := false
		for _, e := range errs {
			if strings.HasPrefix(e, c.k+":") {
				found = true
				if strings.Contains(e, "must be at most") && strings.Contains(e, long) {
					t.Errorf("echoed value")
				}
			}
		}
		if !found {
			t.Errorf("%s/%s=%q not rejected: %v", c.op, c.k, c.v, errs)
		}
	}
}

func TestEveryParameterDefaultValidates(t *testing.T) {
	r := &Registry{}
	for _, op := range builtinOperations {
		for _, p := range op.Parameters {
			if p.Default == "" {
				continue
			}
			if errs := r.ValidateInput(Operation{Parameters: []ParameterDef{p}}, map[string]string{p.Name: p.Default}); len(errs) > 0 {
				t.Errorf("%s/%s default: %v", op.Name, p.Name, errs)
			}
		}
	}
}
