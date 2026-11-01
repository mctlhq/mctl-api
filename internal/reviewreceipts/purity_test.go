package reviewreceipts

import (
	"os/exec"
	"strings"
	"testing"
)

// The package must stay free of I/O and of every store, transport and
// control-plane package.
var forbiddenImports = []string{
	"database/sql",
	"github.com/jackc/pgx",
	"net/http",
	"/internal/api",
	"/internal/auth",
	"/internal/mcp",
	"/internal/lifecycle",
	"/internal/evidence",
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
