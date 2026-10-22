# Contributing

Thanks for helping build Scout.

## Development

```bash
go build ./...
go test ./...
```

Before pushing, run what CI runs:

```bash
gofmt -l .                 # must print nothing
go vet ./...
go test -race ./...
gosec -exclude-dir=ui ./...
```

CI builds and tests with `CGO_ENABLED=0` on Linux, macOS and Windows.

## The dashboard

The React source is in `ui/dashboard`; the build output `ui/dist/` is
committed and embedded, so a Go-only contributor never needs Node. If you
change the dashboard, rebuild and commit `ui/dist`:

```bash
cd ui/dashboard && npm ci && npm run build
```

## Writing a collector

The most valuable contribution right now is a collector. See
[docs/architecture.md](docs/architecture.md#adding-a-collector): implement
`core.Check`, register it in `init()`, make every request through
`core.HTTPClient(ctx)`, and attach a deterministic `Remediation`. Declare the
most aggressive `Mode` the check uses — this is what keeps scans safe.

## Conventions

- Conventional commit messages (`feat:`, `fix:`, `docs:`, `test:`, `ci:`).
- A focused commit per feature, with tests.
- Keep findings deterministic: no time- or order-dependent output.

## Security

Please report vulnerabilities privately — see [SECURITY.md](SECURITY.md).
