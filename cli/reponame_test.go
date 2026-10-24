package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGitRemoteName(t *testing.T) {
	cases := []struct {
		url, want string
	}{
		{"https://github.com/MUKE-coder/scout.git", "MUKE-coder/scout"},
		{"git@github.com:MUKE-coder/scout.git", "MUKE-coder/scout"},
		{"ssh://git@gitlab.com/group/sub/proj.git", "sub/proj"},
		{"https://example.com/only", ""},
	}
	for _, c := range cases {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o750); err != nil {
			t.Fatal(err)
		}
		cfg := "[remote \"origin\"]\n\turl = " + c.url + "\n\tfetch = +refs/heads/*\n"
		if err := os.WriteFile(filepath.Join(dir, ".git", "config"), []byte(cfg), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := gitRemoteName(dir); got != c.want {
			t.Errorf("gitRemoteName(%q) = %q, want %q", c.url, got, c.want)
		}
	}
}

func TestRepoNameFallsBackToFolder(t *testing.T) {
	dir := t.TempDir() // no .git
	want := filepath.Base(dir)
	if got := repoName(dir); got != want {
		t.Errorf("repoName(%q) = %q, want folder name %q", dir, got, want)
	}
}
