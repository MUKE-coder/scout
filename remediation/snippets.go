package remediation

// Snippets: stack-specific remediation code shared by collectors.
// Every snippet is deterministic and copy-pasteable.

import (
	"fmt"

	"github.com/MUKE-coder/scout/core"
)

// Stack names used in core.Fix.Stack.
const (
	Gin     = "gin"
	Nginx   = "nginx"
	Caddy   = "caddy"
	NextJS  = "nextjs"
	Generic = "generic"
)

// SetHeader returns fixes that add a response header on every response.
func SetHeader(name, value string) []core.Fix {
	return []core.Fix{
		{Stack: Gin, Language: "go", Code: fmt.Sprintf(`router.Use(func(c *gin.Context) {
	c.Header(%q, %q)
	c.Next()
})`, name, value)},
		{Stack: Nginx, Language: "nginx", Code: fmt.Sprintf(`# in the server {} block
add_header %s "%s" always;`, name, value)},
		{Stack: Caddy, Language: "caddy", Code: fmt.Sprintf(`header %s "%s"`, name, value)},
		{Stack: NextJS, Language: "js", Code: fmt.Sprintf(`// next.config.js
module.exports = {
  async headers() {
    return [{ source: "/:path*", headers: [{ key: %q, value: %q }] }];
  },
};`, name, value)},
	}
}

// Refs builds a reference list from URLs.
func Refs(urls ...string) []string { return urls }
