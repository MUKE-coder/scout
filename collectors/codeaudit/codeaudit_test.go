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
		"rng.go":    "func f() { sessionToken = rand.Intn(1000000) }\n", // security-relevant → flag
		"jitter.js": "const d = base/2 + Math.random()*(base/2)\n",      // jitter → no flag
		"note.go":   "// we avoid md5 here on purpose\n",                // a comment must not be flagged
	})
	if n := len(run(t, InsecureRandom{}, dir)); n != 1 {
		t.Fatalf("insecure random = %d (want 1: only the security-relevant use)", n)
	}
	if n := len(run(t, WeakCrypto{}, dir)); n != 0 {
		t.Fatalf("comment should not be flagged, got %d", n)
	}
}

// TestFalsePositives locks in the fixes from GitHub issues #4, #5 and #6: the
// patterns below are all legitimate code that must NOT be flagged.
func TestFalsePositives(t *testing.T) {
	dir := repoWith(t, map[string]string{
		// #5: RegExp.exec is not child_process.exec.
		"re.ts": "const m = /^#?([0-9a-f]{3})$/i.exec(raw.trim())\n",
		// #5: Math.random for a width / React key is not security-relevant.
		"ui.tsx": "const w = `${50 + Math.random()*50}%`\nconst k = 'new-'+Math.random().toString(36)\n",
		// #5: a block comment mentioning a sink must not be flagged.
		"doc.tsx": "/*\n dangerouslySetInnerHTML is the only way to inline a script.\n*/\nexport const x = 1\n",
		// #4: a credential word in a format string (logging an error) is not a leak.
		"log.go": "log.Printf(\"auth: preparing the password hash: %v\", err)\n",
		// #6: HMAC-SHA1 (RFC 6238 TOTP) is not broken SHA-1.
		"totp.go": "mac := hmac.New(sha1.New, key)\n",
		// #6: a line annotated #nosec was already human-reviewed.
		"hibp.go": "sum := sha1.Sum([]byte(candidate)) // #nosec G401 -- HIBP range API key, not a password hash\n",
	})
	for _, c := range []core.Check{DangerousSink{}, InsecureRandom{}, SecretLogging{}, WeakCrypto{}} {
		if got := run(t, c, dir); len(got) != 0 {
			t.Errorf("%s produced false positives: %+v", c.ID(), got)
		}
	}
}

func TestUnpinnedDeps(t *testing.T) {
	dir := repoWith(t, map[string]string{
		"package.json": `{
  "dependencies": {
    "next": "16.4.2",
    "react": "^19.3.1",
    "lodash": "*",
    "left-pad": "latest"
  },
  "version": "^1.0.0"
}`,
	})
	got := run(t, UnpinnedDeps{}, dir)
	lines := map[int]bool{}
	for _, f := range got {
		lines[f.Asset.Line] = true
	}
	// react(^), lodash(*), left-pad(latest) are loose; next (exact) and the
	// top-level "version" (outside a deps block) are not.
	if len(got) != 3 {
		t.Fatalf("want 3 loose deps, got %d: %+v", len(got), got)
	}
}

func TestNoRepoNoFindings(t *testing.T) {
	for _, c := range Checks() {
		if got, err := c.Run(context.Background(), core.Target{URL: "https://x", Environment: core.EnvDev}); err != nil || got != nil {
			t.Fatalf("%s url-only: %v %v", c.ID(), got, err)
		}
	}
}
