package gitops

import (
	"os"
	"path/filepath"
	"testing"
)

func TestServicesBySourceRepo(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		p := filepath.Join(root, "platform-gitops", "services", rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ann := func(repo string) string {
		return "metadata:\n  annotations:\n    github.com/source-repo: " + repo + "\n"
	}
	write("b/web/catalog-info.yaml", ann("MctlHQ/Mctl-Telegram"))
	write("a/tg2/catalog-info.yaml", ann("mctlhq/mctl-telegram"))
	write("a/tg1/catalog-info.yaml", ann("mctlhq/mctl-telegram"))
	write("a/other/catalog-info.yaml", ann("x/y"))
	write("a/nofile/values.yaml", "a: 1\n")

	r := &Reader{localPath: root}
	if _, err := r.ServicesBySourceRepo("mctlhq/mctl-telegram"); err == nil {
		t.Fatal("unsynced checkout must be an error")
	}
	r.head = "abc"
	got, err := r.ServicesBySourceRepo("mctlhq/mctl-telegram")
	if err != nil {
		t.Fatal(err)
	}
	want := []SourceRepoBinding{{"a", "tg1"}, {"a", "tg2"}, {"b", "web"}}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}

	write("a/broken/catalog-info.yaml", "metadata: [\n")
	if _, err := r.ServicesBySourceRepo("mctlhq/mctl-telegram"); err == nil {
		t.Fatal("invalid catalog-info must be an error")
	}
	if err := os.Remove(filepath.Join(root, "platform-gitops", "services", "a", "broken", "catalog-info.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("tg1", filepath.Join(root, "platform-gitops", "services", "a", "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ServicesBySourceRepo("mctlhq/mctl-telegram"); err == nil {
		t.Fatal("symlinked app dir must be an error")
	}
}
