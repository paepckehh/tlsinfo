# AGENTS.md

Guide for AI agents (and humans) working in this repository.

## What this is

`paepcke.de/tlsinfo` — a Go library plus CLI that analyzes TLS connections: handshake state, certificate chains, key pins, OCSP status, crypto hygiene. Zero-dependency philosophy: stdlib + `paepcke.de/certinfo` (X.509 analysis) + `paepcke.de/reportstyle` (output styling) + `golang.org/x/crypto` (OCSP parsing) only. Github mirror: github.com/paepckehh/tlsinfo 

## Commands

```sh
make all          # run the CLI against github.com (live network call!)
make examples     # run CLI against github.com and paepcke.de (live network)
make test         # go test ./... (offline, loopback-only TLS test server)
make check        # gofmt -w -s, go vet, go fix, golangci-lint (root + cmd/)
go build ./...    # compile check (CGO_ENABLED=0 everywhere)
go vet ./...
```

- `make check` mutates files (gofmt -w, go fix) — run it and inspect the diff.
- `make deps` is **destructive**: deletes `go.mod`/`go.sum`, re-runs `go mod init paepcke.de/tlsinfo` + `go mod tidy`. Only for deliberate dependency resets.
- Tests: `generic_test.go` (helpers), `api_test.go` (reporters, pins, OCSP-stapling loopback server), `starttls_test.go` (protocol upgrades, STARTTLS e2e), `cmd/tlsinfo/main_test.go` (CLI helpers). All offline; `make test` runs them.
- Latest tag: see `git tag --sort=-v:refname | head -1`. Releases are cut by goreleaser on any `v*` tag push.

## Layout & architecture

```
api.go            public library API + generic backend (the core)
generic.go        unexported helpers (consts, version table, splitAddr, addPort, ...)
starttls.go       STARTTLS backend: protocol identifiers, ports, upgrade dialer
api_test.go       offline unit tests (loopback TLS server + OCSP staple)
generic_test.go   offline unit tests for the unexported helpers
starttls_test.go  offline unit tests for the STARTTLS upgrades
cmd/tlsinfo/      CLI main — thin wrapper, all logic lives in the root package
llms.txt           AI-friendly repo overview (LLM entrypoint, keep in sync)
```

Three-layer API in `api.go`, top-down:

1. **Simple API** — style-fixed wrappers: `ReportHostText/HTML`, `ReportStartTLSText/HTML`, `PinHost`, `PinVerifyHost`, `PinStartTLS`, `PinVerifyStartTLS`, ...
2. **Generic backend** — `ReportHost(host, *tls.Config, *reportstyle.Style)` → `ReportConn` → `ReportTlsState` (pure, works from `tls.ConnectionState`). STARTTLS via `starttlsDial` (plaintext `net.Dial` → protocol negotiation → `tls.Client` handshake). OCSP via `ReportOcsp`.
3. **External** — `certinfo.CertStore(s)` renders certificate details, `reportstyle.Style` (L1/L2/L3/LE/Raw) renders lines.

Data flow: hostname → `addCheckPort`/`addStarttlsPort` (append default port, bracket bare IPv6 literals) → `tls.Dial` (or `net.Dial` + STARTTLS negotiation + `tls.Client`) → `tls.Conn` → `ConnectionState` → assembled report string. `ReportHttpRequest` is the server-side variant (report your own clients from an HTTP handler).

## Conventions (observed, not documented anywhere else)

- **Doc comments are one-liners**: `// FuncName ...` — nothing more. Match this.
- **Section banners**: `//` blank, `// SECTION NAME`, `//` between API groups.
- **Unexported constants are underscore-prefixed**: `_tcp`, `_sslport`, `_app`.
- **Errors are embedded in return strings** (`"[tlsinfo] [error] ..."` / `"[starttls] [error] ..."` — the leading tag names the failing component), not `(string, error)` tuples. Library API returns plain strings; keep that shape.
- **CLI config is env-vars only, no flags**: `NO_COLOR`, `VERBOSE` (enables raw/PEM/OpenSSL detail), `HTML`, `PINONLY`, `STARTTLS` (protocol identifier: `smtp`, `imap`, `pop3`, `nntp`, `ftp` — also combines with `PINONLY`), `PEMONLY` (**currently a no-op** — `PemHost` call is commented out in `cmd/tlsinfo/main.go`). Env vars are only "on" when set to a **non-empty** value (`isEnv`, per no-color.org: `NO_COLOR=""` keeps colors).
- **Piped stdin beats argv** in the CLI: check `isPipe()` branch order in `main.go` before changing input handling. Pipe input is whitespace-split via `pipeHosts()` (trims trailing newlines, supports multi-host pipes); `PINONLY`/`PEMONLY`/`STARTTLS` apply to both input paths via the `report()` helper.
- `gofmt -s` (simplify) formatting; CGO disabled in Makefile, CI, and `.goreleaser.yml`.
- Dependency bumps arrive via Dependabot PRs, commit style `build(deps): bump <module> from X to Y`.
- **STARTTLS backend lives in `starttls.go`**: exported protocol identifiers (`SMTP`, `IMAP`, `POP3`, `NNTP`, `FTP`) map to **one** table `_starttlsProtocols` (rows are `starttlsDef{port, sequence}`: default plaintext port + negotiation steps of command + expected response prefix). The unsupported-protocol error comes from the shared helper `starttlsUnsupported`. `starttlsDial` sets `InsecureSkipVerify` + infers `ServerName` (like `tls.Dial`), puts a 30s deadline on the plaintext phase (`_dialWait`).

## Gotchas

- `ReportHost` **deliberately sets `t.InsecureSkipVerify = true`** — and mutates the caller's `*tls.Config` in place. It must: reporting untrusted/invalid chains is the tool's purpose. Do not "fix" this.
- `PinHostWithTLS` sets `InsecureSkipVerify` too (TOFU pinning must fetch pins from untrusted/self-signed chains), and every dial (`tls.DialWithDialer` in `ReportHost`/`PinHostWithTLS`, `starttlsDial`) carries a 30s cap (`_dialWait`, defined in `generic.go`) so the CLI cannot hang forever on stalled handshakes.
- The `//nolint:all` on the `TLS Uniq ID` line in `ReportTlsState` is intentional (kept as informative output despite linter security concerns).
- `ReportTlsState` applies `VERBOSE` (`e.Raw`) raw/PEM/OpenSSL detail to **both** the verified-chains and peer-certs sections — the flag is set on `certReport` before the first render; don't move it between the two.
- gopls/`staticcheck` flag ~38 "inefficient string concatenation in WriteString" warnings in `api.go`. Pre-existing and accepted style here — don't rewrite report assembly wholesale.
- `ReportOcsp` guards on `len(ocspResponse) > 8`; the `// @UPSTREAM` comment about `Response.Status` is load-bearing: it is a plain `int` `{Good=0|Revoked=1|Unknown=2}` (certificate status), NOT `ocsp.ResponseStatus` (protocol status: success/malformed/...) — never re-cast it into `ResponseStatus`.
- `ReportOcsp` expects the **issuer** cert (`ocsp.ParseResponse` verifies the stapled signature against it): `ReportConn` passes `PeerCertificates[1]`, falling back to `[0]` for leaf-only chains.
- `ReportTlsState` must survive a nil `ConnectionState` (guard → zero-value report); `splitAddr` maps empty/portless addresses to `"[none]"` — both pinned by tests.
- `ConnectionState.ServerName` is empty for IP-literal targets (Go zeroes SNI for IPs, `hostnameInSNI` in `crypto/tls`) — not a tlsinfo bug; same for plain `tls.Dial`. Test `127.0.0.1` STARTTLS targets accordingly.
- Unbracketed IPv6 literals (`2001:db8::1`) get bracketed by `addPort` before port append; `host:port` with bare IPv6 is ambiguous input (stdlib requires brackets) and fails dial with a clear error.
- go.mod declares `go 1.27.1`, but CI (`.github/workflows/golang.yml`) pins go 1.21 — works only via Go toolchain auto-download. Don't lower go.mod.
- `version()` in `generic.go` hard-codes TLS token labels incl. `[SECURITY ALERT]` verdicts — update both the extended and plain switch tables together.

## Finishing a task (repo owner's standing rule)

1. `gofmt`/`make check`, build, test (if any).
2. Commit: `git add . && git commit -m '<message>'`.
3. Tag patch bump: result is `v0.X.<N+1>` from the latest existing tag.
4. Push commits **and** tag: `git push && git push origin <tag>`.
5. Update this AGENTS.md in the same change when commands/conventions shift.
