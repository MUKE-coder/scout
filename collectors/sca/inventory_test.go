package sca

import (
	"testing"

	"github.com/MUKE-coder/scout/intel"
)

func lookup(pkgs []intel.Package, eco, name string) (string, bool) {
	for _, p := range pkgs {
		if p.Ecosystem == eco && p.Name == name {
			return p.Version, true
		}
	}
	return "", false
}

func TestParsers(t *testing.T) {
	cases := []struct {
		name, file, body, eco, pkg, want string
	}{
		{"npm v3", "package-lock.json", `{"packages":{"":{"name":"app"},"node_modules/lodash":{"version":"4.17.11"}}}`, "npm", "lodash", "4.17.11"},
		{"go.mod", "go.mod", "module x\n\ngo 1.24\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.0\n)\n", "Go", "github.com/gin-gonic/gin", "1.9.0"},
		{"requirements", "requirements.txt", "flask==2.0.1\n# comment\n", "PyPI", "flask", "2.0.1"},
		{"requirements normalize", "requirements.txt", "Django == 3.2.0\n", "PyPI", "django", "3.2.0"},
		{"pipfile", "Pipfile.lock", `{"default":{"requests":{"version":"==2.25.0"}}}`, "PyPI", "requests", "2.25.0"},
		{"composer", "composer.lock", `{"packages":[{"name":"monolog/monolog","version":"v1.0.0"}]}`, "Packagist", "monolog/monolog", "1.0.0"},
		{"cargo", "Cargo.lock", "[[package]]\nname = \"serde\"\nversion = \"1.0.1\"\n", "crates.io", "serde", "1.0.1"},
		{"poetry", "poetry.lock", "[[package]]\nname = \"Flask\"\nversion = \"2.0.1\"\n", "PyPI", "flask", "2.0.1"},
		{"gemfile", "Gemfile.lock", "GEM\n  specs:\n    rails (6.1.0)\n    rake (13.0.1)\n", "RubyGems", "rails", "6.1.0"},
		{"nuget", "packages.lock.json", `{"dependencies":{"net6.0":{"Newtonsoft.Json":{"resolved":"12.0.1"}}}}`, "NuGet", "Newtonsoft.Json", "12.0.1"},
		{"maven", "pom.xml", `<project><dependencies><dependency><groupId>org.springframework</groupId><artifactId>spring-core</artifactId><version>5.3.0</version></dependency></dependencies></project>`, "Maven", "org.springframework:spring-core", "5.3.0"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := parsers[c.file]
			if p == nil {
				t.Fatalf("no parser for %s", c.file)
			}
			got := p(c.file, []byte(c.body))
			v, ok := lookup(got, c.eco, c.pkg)
			if !ok {
				t.Fatalf("%s %s not found in %+v", c.eco, c.pkg, got)
			}
			if v != c.want {
				t.Errorf("version = %q, want %q", v, c.want)
			}
		})
	}
}

func TestMavenSkipsUnresolved(t *testing.T) {
	body := `<project><dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId><version>${spring.version}</version></dependency></dependencies></project>`
	if got := parsers["pom.xml"]("pom.xml", []byte(body)); len(got) != 0 {
		t.Fatalf("property version should be skipped, got %+v", got)
	}
}
