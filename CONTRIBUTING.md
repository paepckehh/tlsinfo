# Contributing to tlsinfo

Thanks for your interest in improving `tlsinfo`! Issues and pull requests are both welcome — this guide gets you productive in under ten minutes.

## Getting started

```shell
git clone https://github.com/paepckehh/tlsinfo
cd tlsinfo

make test    # offline unit tests, loopback-only TLS server — no network needed
make check   # gofmt -w -s, go vet, go fix, golangci-lint (root + cmd/)
```

`make examples` and `make all` run the CLI against live hosts (`github.com`, `paepcke.de`).

## Ground rules

- **Keep diffs minimal and focused** — one topic per pull request.
- **`make test` and `make check` must pass.** `make check` mutates files (`gofmt -w`, `go fix`) — run it locally and commit the result.
- **Zero-dependency philosophy**: stdlib + `paepcke.de/certinfo` + `paepcke.de/reportstyle` + `golang.org/x/crypto` only. New dependencies need a very strong reason.
- **No CLI flags**: configuration is env-vars only (`NO_COLOR`, `VERBOSE`, `HTML`, `PINONLY`, `STARTTLS`).
- **Library API returns strings** — errors are embedded as `[tlsinfo] [error] ...` / `[starttls] [error] ...`, not `(string, error)` tuples.
- **Commit style**: conventional — `feat:`, `fix:`, `docs:`, `build(deps): bump <module> from X to Y`.

## Reporting issues

- Include the command you ran, the host (if public), and the output or error you got.
- A minimal reproduction helps a lot — `tlsinfo <host>` output is usually enough.
- **Do not open public issues for security vulnerabilities** — see [SECURITY.md](SECURITY.md) instead.

## Releases

Every `v*` tag push triggers a [goreleaser](https://goreleaser.com) build with prebuilt binaries for all platforms. Versioning is `v0.X.Y` — patch bumps for fixes and docs, minor bumps for features.
