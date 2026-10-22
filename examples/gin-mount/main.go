// Command gin-mount is a minimal Gin application that mounts Scout with one
// line. Run it, then open http://localhost:8080/scout/ui/ for the dashboard
// (dev mode accepts the default admin / scout login).
//
//	go run ./examples/gin-mount
//
// From another terminal you can scan it once collectors exist:
//
//	scout scan --target http://localhost:8080 --mode safe
package main

import (
	"net/http"

	"github.com/gin-gonic/gin"

	scout "github.com/MUKE-coder/scout"
)

func main() {
	r := gin.Default()

	// The app's own routes.
	r.GET("/", func(c *gin.Context) { c.String(http.StatusOK, "todo app") })
	api := r.Group("/api")
	api.GET("/todos", func(c *gin.Context) { c.JSON(http.StatusOK, []string{"buy milk"}) })
	api.POST("/todos", func(c *gin.Context) { c.Status(http.StatusCreated) })

	// One line mounts Scout at /scout: dashboard, API, health and the live
	// WebSocket. It also exposes this router's route table to the scanner,
	// so Scout can flag unprotected routes before sending any traffic.
	scout.Mount(r, scout.Config{AppName: "Todo API"})

	_ = r.Run(":8080")
}
