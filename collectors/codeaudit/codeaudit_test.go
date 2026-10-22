package codeaudit

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/MUKE-coder/scout/core"
)

func repoWith(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func run(t *testing.T, c core.Check, dir string) []core.Finding {
	t.Helper()
	got, err := c.Run(context.Background(), core.Target{Repo: dir, Environment: core.EnvDev})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestWeakCrypto(t *testing.T) {
	dir := repoWith(t, map[string]string{
		"hash.go":   "import \"crypto/md5\"\nfunc h() { md5.New() }\n",
		"token.js":  "const h = crypto.createHash('sha1')\n",
		"strong.go": "import \"crypto/sha256\"\nfunc h() { sha256.New() }\n",
	})
	got := run(t, WeakCrypto{}, dir)
	files := map[string]bool{}
	for _, f := range got {
		files[f.Asset.File] = true
	}
	if !files["hash.go"] || !files["token.js"] {
		t.Fatalf("missed weak crypto: %v", files)
	}
	if files["strong.go"] {
		t.Error("sha256 should not be flagged")
	}
}

func TestDangerousSink(t *testing.T) {
	dir := repoWith(t, map[string]string{
		"a.js":  "const r = eval(userInput)\n",
		"b.go":  "exec.Command(\"sh\", \"-c\", userCmd)\n",
		"c.jsx": "<div dangerouslySetInnerHTML={{__html: q}} />\n",
		"ok.js": "const sum = 1 + 2\n",
	})
	n := len(run(t, DangerousSink{}, dir))
	if n < 3 {
		t.Fatalf("expected >=3 dangerous sinks, got %d", n)
	}
}

func TestSecretLogging(t *testing.T) {
	dir := repoWith(t, map[string]string{
		"log.js": "console.log('user password is', password)\n",
		"ok.js":  "console.log('request complete')\n",
	})
	got := run(t, SecretLogging{}, dir)
	if len(got) != 1 || got[0].Asset.File != "log.js" || got[0].CWE[0] != "CWE-532" {
		t.Fatalf("secret logging = %+v", got)
	}
}

func TestInsecureRandomAndComments(t *testing.T) {
	dir := repoWith(t, map[string]string{
		"rng.go":  "import \"math/rand\"\n",
		"note.go": "// we avoid md5 here on purpose\n", // a comment must not be flagged
	})
	if n := len(run(t, InsecureRandom{}, dir)); n != 1 {
		t.Fatalf("insecure random = %d", n)
	}
	if n := len(run(t, WeakCrypto{}, dir)); n != 0 {
		t.Fatalf("comment should not be flagged, got %d", n)
	}
}

func TestNoRepoNoFindings(t *testing.T) {
	for _, c := range Checks() {
		if got, err := c.Run(context.Background(), core.Target{URL: "https://x", Environment: core.EnvDev}); err != nil || got != nil {
			t.Fatalf("%s url-only: %v %v", c.ID(), got, err)
		}
	}
}
