package executionprovenance

import (
	"os/exec"
	"strings"
	"testing"
)

var forbiddenImports = []string{
	"database/sql",
	"github.com/jackc/pgx",
	"net/http",
	"/internal/api",
	"/internal/auth",
	"/internal/mcp",
	"/internal/lifecycle",
	"/internal/evidence",
	"/internal/workitems",
}

func TestPackageDependsOnNoForbiddenImport(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", ".").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	for _, dep := range strings.Fields(string(out)) {
		for _, bad := range forbiddenImports {
			if dep == bad || strings.HasPrefix(dep, bad+"/") || (strings.HasPrefix(bad, "/") && strings.Contains(dep, bad)) {
				t.Errorf("forbidden dependency %s (matches %s)", dep, bad)
			}
		}
	}
}
