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

func TestIsRemoteRepo(t *testing.T) {
	remote := []string{
		"https://github.com/MUKE-coder/gorm-studio",
		"http://example.com/x/y",
		"git@github.com:owner/repo.git",
		"ssh://git@host/owner/repo.git",
		"git://host/repo",
	}
	local := []string{".", "./sub", "/abs/path", "C:\\repo", "repo"}
	for _, s := range remote {
		if !isRemoteRepo(s) {
			t.Errorf("isRemoteRepo(%q) = false, want true", s)
		}
	}
	for _, s := range local {
		if isRemoteRepo(s) {
			t.Errorf("isRemoteRepo(%q) = true, want false", s)
		}
	}
}

func TestOwnerRepoFromGitURL(t *testing.T) {
	cases := map[string]string{
		"https://github.com/MUKE-coder/gorm-studio":     "MUKE-coder/gorm-studio",
		"https://github.com/MUKE-coder/gorm-studio.git": "MUKE-coder/gorm-studio",
		"git@github.com:owner/repo.git":                 "owner/repo",
		"https://example.com/only":                      "",
	}
	for in, want := range cases {
		if got := ownerRepoFromGitURL(in); got != want {
			t.Errorf("ownerRepoFromGitURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCloneURLInjectsToken(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("SCOUT_GIT_TOKEN", "secret123")
	got := cloneURL("https://github.com/owner/repo")
	want := "https://x-access-token:secret123@github.com/owner/repo"
	if got != want {
		t.Errorf("cloneURL = %q, want %q", got, want)
	}
	// SSH URLs and already-credentialed URLs are untouched.
	if u := cloneURL("git@github.com:owner/repo.git"); u != "git@github.com:owner/repo.git" {
		t.Errorf("ssh url changed: %q", u)
	}
}

func TestRepoNameFallsBackToFolder(t *testing.T) {
	dir := t.TempDir() // no .git
	want := filepath.Base(dir)
	if got := repoName(dir); got != want {
		t.Errorf("repoName(%q) = %q, want folder name %q", dir, got, want)
	}
}
