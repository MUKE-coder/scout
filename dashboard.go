package scout

import (
	"io/fs"
	"net/http"
	"path"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/MUKE-coder/scout/ui"
)

// dashboardHandler serves the embedded single-page app. Real files (hashed
// assets) are served directly and cached for a year; every other path gets
// index.html so client-side routes survive a refresh.
func dashboardHandler(dist fs.FS) gin.HandlerFunc {
	index, err := fs.ReadFile(dist, "index.html")
	if err != nil {
		panic("scout: embedded dashboard is missing index.html; run npm run build in ui/dashboard")
	}
	files := http.FileServer(http.FS(dist))
	return func(c *gin.Context) {
		p := strings.TrimPrefix(path.Clean(c.Param("path")), "/")
		if p != "" && p != "." && p != "index.html" {
			if info, err := fs.Stat(dist, p); err == nil && !info.IsDir() {
				if strings.HasPrefix(p, "assets/") {
					c.Header("Cache-Control", "public, max-age=31536000, immutable")
				}
				c.Request.URL.Path = "/" + p
				files.ServeHTTP(c.Writer, c.Request)
				return
			}
		}
		c.Header("Cache-Control", "no-cache")
		c.Data(http.StatusOK, "text/html; charset=utf-8", index)
	}
}

func registerDashboard(g *gin.RouterGroup) {
	g.GET("/ui", func(c *gin.Context) { c.Redirect(http.StatusMovedPermanently, UIPath+"/") })
	g.GET("/ui/*path", dashboardHandler(ui.Dist()))
}
