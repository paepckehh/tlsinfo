# AGENTS.md

Guide for AI agents (and humans) working in this repository.

## What this is

`paepcke.de/tlsinfo` — a Go library plus CLI that analyzes TLS connections: handshake state, certificate chains, key pins, OCSP status, crypto hygiene. Zero-dependency philosophy: stdlib + `paepcke.de/certinfo` (X.509 analysis) + `paepcke.de/reportstyle` (output styling) + `golang.org/x/crypto` (OCSP parsing) only.

## Commands

```sh
make all          # run the CLI against github.com (live network call!)
make examples     # run CLI against github.com and paepcke.de (live network)
make check        # gofmt -w -s, go vet, go fix, golangci-lint (root + cmd/)
go build ./...    # compile check (CGO_ENABLED=0 everywhere)
go vet ./...
```

- `make check` mutates files (gofmt -w, go fix) — run it and inspect the diff.
- `make deps` is **destructive**: deletes `go.mod`/`go.sum`, re-runs `go mod init paepcke.de/tlsinfo` + `go mod tidy`. Only for deliberate dependency resets.
- There are **no tests**. Verification = `make check` + `go build ./...` + `make examples` (needs internet).
- Latest tag: see `git tag --sort=-v:refname | head -1`. Releases are cut by goreleaser on any `v*` tag push.

## Layout & architecture

```
api.go            public library API + generic backend (the core)
generic.go        unexported helpers (consts, version table, addCheckPort, ...)
cmd/tlsinfo/      CLI main — thin wrapper, all logic lives in the root package
```

Three-layer API in `api.go`, top-down:

1. **Simple API** — style-fixed wrappers: `ReportHostText/HTML`, `PinHost`, `PinVerifyHost`, ...
2. **Generic backend** — `ReportHost(host, *tls.Config, *reportstyle.Style)` → `ReportConn` → `ReportTlsState` (pure, works from `tls.ConnectionState`). OCSP via `ReportOcsp`.
3. **External** — `certinfo.CertStore(s)` renders certificate details, `reportstyle.Style` (L1/L2/L3/LE/Raw) renders lines.

Data flow: hostname → `addCheckPort` (append `:443` if no port) → `tls.Dial` → `tls.Conn` → `ConnectionState` → assembled report string. `ReportHttpRequest` is the server-side variant (report your own clients from an HTTP handler).

## Conventions (observed, not documented anywhere else)

- **Doc comments are one-liners**: `// FuncName ...` — nothing more. Match this.
- **Section banners**: `//` blank, `// SECTION NAME`, `//` between API groups.
- **Unexported constants are underscore-prefixed**: `_tcp`, `_sslport`, `_app`.
- **Errors are embedded in return strings** (`"[certinfo] [error] ..."`), not `(string, error)` tuples. Library API returns plain strings; keep that shape.
- **CLI config is env-vars only, no flags**: `NO_COLOR`, `VERBOSE` (enables raw/PEM/OpenSSL detail), `HTML`, `PINONLY`, `PEMONLY` (**currently a no-op** — `PemHost` call is commented out in `cmd/tlsinfo/main.go`).
- **Piped stdin beats argv** in the CLI: check `isPipe()` branch order in `main.go` before changing input handling.
- `gofmt -s` (simplify) formatting; CGO disabled in Makefile, CI, and `.goreleaser.yml`.
- Dependency bumps arrive via Dependabot PRs, commit style `build(deps): bump <module> from X to Y`.

## Gotchas

- `ReportHost` **deliberately sets `t.InsecureSkipVerify = true`** — and mutates the caller's `*tls.Config` in place. It must: reporting untrusted/invalid chains is the tool's purpose. Do not "fix" this.
- The `//nolint:all` on the `TLS Uniq ID` line in `ReportTlsState` is intentional (kept as informative output despite linter security concerns).
- gopls/`staticcheck` flag ~38 "inefficient string concatenation in WriteString" warnings in `api.go`. Pre-existing and accepted style here — don't rewrite report assembly wholesale.
- `ReportOcsp` guards on `len(ocspResponse) > 8`; the `// @UPSTREAM` comment about `ocsp.ResponseStatus` is load-bearing.
- go.mod declares `go 1.27.1`, but CI (`.github/workflows/golang.yml`) pins go 1.21 — works only via Go toolchain auto-download. Don't lower go.mod.
- `version()` in `generic.go` hard-codes TLS token labels incl. `[SECURITY ALERT]` verdicts — update both the extended and plain switch tables together.

## Finishing a task (repo owner's standing rule)

1. `gofmt`/`make check`, build, test (if any).
2. Commit: `git add . && git commit -m '<message>'`.
3. Tag patch bump: result is `v0.X.<N+1>` from the latest existing tag.
4. Push commits **and** tag: `git push && git push origin <tag>`.
5. Update this AGENTS.md in the same change when commands/conventions shift.
