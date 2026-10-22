// Package scout is a self-hosted vulnerability scanner and attack-surface
// mapper. Point it at your app. See every way in.
//
// The simplest integration is one line in a Gin app:
//
//	scout.Mount(router, scout.Config{AppName: "My API"})
package scout
