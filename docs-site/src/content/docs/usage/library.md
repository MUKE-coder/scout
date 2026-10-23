---
title: Embed in a Go app (Mount)
description: Mount Scout into your own Gin app to expose its dashboard and API, with the real route table fed in for accurate auth checks.
---

Scout is a library as well as a CLI. `scout.Mount` attaches its dashboard and API
to an existing [Gin](https://gin-gonic.com/) router, so your app ships with Scout
built in.

## Mount it

```go
package main

import (
    "github.com/gin-gonic/gin"
    "github.com/MUKE-coder/scout"
    _ "github.com/MUKE-coder/scout/collectors/all" // register every check
)

func main() {
    r := gin.Default()

    // your routes …
    r.GET("/api/account", accountHandler)

    cfg, _ := scout.NewConfig(
        scout.WithTarget("http://localhost:8080"),
        scout.WithEnvironment(scout.EnvDev),
    )
    s, _ := scout.Mount(r, cfg)
    _ = s

    r.Run(":8080") // Scout is now served under /scout
}
```

:::note
The blank import of `collectors/all` is what registers the checks. Without it,
Scout mounts but has nothing to run.
:::

## Feed in your route table

Scout's "unprotected route" check is far more accurate when it knows each route's
authorization middleware. `Mount` introspects Gin's routes automatically, but you
can hand it a richer table with `WithRoutes` — including the middleware chain:

```go
cfg, _ := scout.NewConfig(
    scout.WithTarget("http://localhost:8080"),
    scout.WithRoutes(
        core.Route{Method: "GET", Path: "/api/account", Middleware: []string{"AuthRequired"}},
        core.Route{Method: "GET", Path: "/api/admin", Middleware: []string{"Logger"}}, // no auth → flagged
    ),
)
```

The resolved table is also exposed at `GET /scout/api/routes`.

## Add test identities for IDOR

```go
cfg, _ := scout.NewConfig(
    scout.WithTarget("http://localhost:8080"),
    scout.WithTestIdentities(
        core.Identity{Name: "alice", Headers: map[string]string{"Cookie": "session=a"}, Owns: []string{"/api/users/1"}},
        core.Identity{Name: "bob", Headers: map[string]string{"Cookie": "session=b"}, Owns: []string{"/api/users/2"}},
    ),
)
```

See [IDOR & test identities](/usage/idor/) for how the comparison works.

## Config options

`NewConfig` takes functional options: `WithTarget`, `WithMode`, `WithEnvironment`,
`WithScope`, `WithDB`, `WithRoutes`, `WithTestIdentities`, and `WithConfig` to
start from a full struct. See [Configuration](/reference/configuration/).
