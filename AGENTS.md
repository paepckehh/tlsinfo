# AGENTS.md

Guide for AI agents (and humans) working in this repository.

## What this is

`paepcke.de/tlsinfo` — a Go library plus CLI that analyzes TLS connections: handshake state, certificate chains, key pins, OCSP status, crypto hygiene. Zero-dependency philosophy: stdlib + `paepcke.de/certinfo` (X.509 analysis) + `paepcke.de/reportstyle` (output styling) + `golang.org/x/crypto` (OCSP parsing) only. Github mirror: github.com/paepckehh/tlsinfo 

## Commands

```sh
make all          # build (with version ldflags) and run the CLI against github.com (live network!)
make build        # CGO_ENABLED=0 go build with -X main._version=<git tag> into ./tlsinfo
make version      # print the semver tracked from the latest git tag
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
docs/hero-dark.svg  theme-aware README banner, dark (hand-built SVG dashboard)
docs/hero-light.svg theme-aware README banner, light (same layout, light palette)
docs/established-dark.svg  theme-aware "established 2022" banner below the badge row, dark
docs/established-light.svg theme-aware "established 2022" banner below the badge row, light
docs/demo-report.svg terminal capture of `tlsinfo github.com` rendered as SVG
docs/demo-alert.svg  terminal capture of `tlsinfo expired.badssl.com` (red verdicts)
```

Three-layer API in `api.go`, top-down:

1. **Simple API** — style-fixed wrappers: `ReportHostText/HTML`, `ReportStartTLSText/HTML`, `PinHost`, `PinVerifyHost`, `PinStartTLS`, `PinVerifyStartTLS`, ...
2. **Generic backend** — `ReportHost(host, *tls.Config, *reportstyle.Style)` → `ReportConn` → `ReportTlsState` (pure, works from `tls.ConnectionState`). STARTTLS via `starttlsDial` (plaintext `net.DialTimeout` → protocol negotiation → `tls.Client` handshake). OCSP via `ReportOcsp`.
3. **External** — `certinfo.CertStore(s)` renders certificate details, `reportstyle.Style` (L1/L2/L3/LE/Raw) renders lines.

Data flow: hostname → `addCheckPort`/`addStarttlsPort` (append default port, bracket bare IPv6 literals) → `tls.Dial` (or `net.DialTimeout` + STARTTLS negotiation + `tls.Client`) → `tls.Conn` → `ConnectionState` → assembled report string. `ReportHttpRequest` is the server-side variant (report your own clients from an HTTP handler).

## Conventions (observed, not documented anywhere else)

- **Doc comments are one-liners**: `// FuncName ...` — nothing more. Match this.
- **Section banners**: `//` blank, `// SECTION NAME`, `//` between API groups.
- **Unexported constants are underscore-prefixed**: `_tcp`, `_sslport`, `_app`.
- **Errors are embedded in return strings** (`"[tlsinfo] [error] ..."` / `"[starttls] [error] ..."` — the leading tag names the failing component), not `(string, error)` tuples. Library API returns plain strings; keep that shape, and keep the tag at the **start** of the string: the CLI detects failures with `isErr()` (prefix match), so an error embedded mid-report must not drive the exit code. The tag belongs to the **exported boundary only**: internal helpers (`reply`, `readLine`, `starttlsUnsupported`) return untagged causes and `PinStartTLS`/`ReportStartTLS` add exactly one `[starttls] [error] [connect] <host> -> ...` wrapper (pinned by the tag-count assertion in `TestReportStartTLS`).
- **CLI is stdlib-`flag` POSIX style, no external CLI library** (zero-dependency philosophy, single-purpose tool): `-starttls <proto>`, `-pin`, `-verbose`, `-html`, `-no-color`, `-version`. Env vars `STARTTLS` (protocol identifier: `smtp`, `imap`, `pop3`, `nntp`, `ftp` — combines with `-pin`), `PINONLY`, `VERBOSE` (raw/PEM/OpenSSL detail), `HTML`, `NO_COLOR` are kept as **fallback flag defaults** for backward compat; a flag always beats the env var. Env vars are only "on" when set to a **non-empty** value (`isEnv`, per no-color.org: `NO_COLOR=""` keeps colors). The dead `PEMONLY` no-op branch was removed — add a `-pem` flag only together with a real `PemHost` library function. Flags must precede hosts (`checkArgs` rejects flag-like positionals, exit 2).
- **CLI exit codes**: `0` all host checks succeeded, `1` at least one host report is a top-level `[tlsinfo] [error]` / `[starttls] [error]` string (unreachable/failed handshake), `2` usage error (flag package `ExitOnError`, flags after hosts, or no hosts at all).
- **Version**: `var _version = "dev"` in `cmd/tlsinfo/main.go`, injected at build time via `-ldflags "-X main._version=<git tag>"` (root `make build`, `cmd/tlsinfo` Makefile `LDFLAGS`, and `.goreleaser.yml` `{{ .Tag }}` — keep all three in sync with the tag). `buildVersion()` prefers the injected tag and otherwise falls back to `debug.ReadBuildInfo()` (`bi.Main.Version`), so `go install ...@latest` and VCS-stamped local builds print a real semver instead of `dev`. Shown on stderr at startup, in `-h` usage header, and via `-version` (stdout) — pinned by `TestBuildVersion`.
- **Piped stdin beats argv** in the CLI, but only when the pipe carries hosts: `inputHosts()` uses `pipeHosts()` when non-empty and falls back to `flag.Args()` otherwise; no hosts at all is a usage error (exit 2). Pipe input is whitespace-split (trims trailing newlines, supports multi-host pipes); all flags apply to both input paths via the `report()` helper. `out()` appends the newline the library error/pin strings do not carry and exits `1` with a tagged stderr message when stdout cannot be written (no panic on `/dev/full` or a closed pipe).
- `gofmt -s` (simplify) formatting; CGO disabled in Makefile, CI, and `.goreleaser.yml`.
- **`.goreleaser.yml` is a goreleaser v2 config** (`version: 2`): `go mod tidy` pre-hook, `-s -w` ldflags strip, CGO_ENABLED=0, GitHub changelog (`use: github`) grouped by conventional-commit type (`feat` → Features, `fix` → Bug fixes, `perf|refactor|improve` → Improvements, `docs` → Documentation, `ci|build|chore` → CI & Build, rest → Others; `docs:`/`test:`/`chore:` commits excluded), plus deb/rpm `nfpms` packages. `.github/workflows/release.yml` pins checkout/setup-go/goreleaser-action@v7 and goreleaser v2.18.2, triggers on `v*` tag push (or manual dispatch), needs `contents: write` — keep it in sync with `../opnborg`, the working reference. `.github/workflows/golang.yml` also uses `@v7` + `go-version-file: go.mod` (no hardcoded Go version).
- Dependency bumps arrive via Dependabot PRs, commit style `build(deps): bump <module> from X to Y`.
- **README terminal demos are real captures.** `docs/demo-report.svg` and `docs/demo-alert.svg` contain the actual colored CLI output for `tlsinfo github.com` and `tlsinfo expired.badssl.com`, including the startup version line; colors are mapped 1:1 from the ANSI codes the CLI emits (`2;93` labels, `2;94` values, `2;92` valid, `2;91` fail) — do not tint tokens the CLI does not tint. Regenerate them from a live run rather than inventing output, and keep the hero banners' terminal card consistent with the real report layout.
- **STARTTLS backend lives in `starttls.go`**: exported protocol identifiers (`SMTP`, `IMAP`, `POP3`, `NNTP`, `FTP`) map to **one** table `_starttlsProtocols` (rows are `starttlsDef{port, sequence}`: default plaintext port + negotiation steps of command + expected response prefix). The unsupported-protocol error comes from `starttlsUnsupported` and derives its protocol list from the table (`starttlsSupported`, sorted). `starttlsDial` trims/lowercases the protocol identifier, clones the caller's config, sets `InsecureSkipVerify` + infers `ServerName` (like `tls.Dial`), dials with `net.DialTimeout` (30s `_dialWait` cap — a bare `net.Dial` hangs for minutes on firewalled/dropped SYN ports), and re-arms a fresh 30s deadline before the TLS handshake so negotiation and handshake each get their own window.

## Gotchas

- `ReportHost`, `PinHostWithTLS` and `starttlsDial` **deliberately set `InsecureSkipVerify = true`** on a **cloned** `*tls.Config` — reporting untrusted/invalid chains is the tool's purpose, and the caller's config must stay untouched (pinned by `TestConfigNotMutated`). Do not "fix" the skip-verify policy; do not reintroduce mutation.
- All dials (`tls.DialWithDialer` in `ReportHost`/`PinHostWithTLS`, `starttlsDial`) carry a 30s cap (`_dialWait`, defined in `generic.go`) so the CLI cannot hang forever on stalled handshakes.
- **Every dynamic value written next to a style marker goes through `esc(value, style)`** (`Style.SaniFunc`): server name, ALPN, remote addresses, HTTP proto/transfer encoding, error text. Cert blocks are already sanitized inside `certinfo` (PS/PE), so never pass them through `esc` again (double escaping). HTML injection is pinned by `TestReportTlsStateHTML`; the CLI's own error strings are escaped inside `ReportHost`/`ReportStartTLS`.
- Report assemblers wrap their output with `document(body, style)` (`Style.Start`/`End`); `ReportConn`/`ReportHttpRequest` call the raw `tlsState` helper, `ReportTlsState` wraps it, so nothing is wrapped twice. Text/ANSI styles define no `Start`/`End` and are unaffected.
- Nil-tolerance is part of the API: `styleOr()` defaults a nil style to `StyleText()`, `ReportConn`/`ReportHttpRequest`/`ReportOcsp` return a tagged error for nil inputs, `PinVerifyConn`/`PinVerifyState` return false, `state == nil` renders a zero-value report — pinned by `TestNilArguments`.
- **Pin verification never matches a failed lookup**: `PinVerifyHostWithTLS`/`PinVerifyStartTLS` use `isTaggedError()` so a `keyPin` equal to the dial error text cannot turn into `true` — pinned by `TestPinVerifyFailure`.
- The `//nolint:all` on the `TLS Uniq ID` line in `ReportTlsState` is intentional (kept as informative output despite linter security concerns).
- `ReportTlsState` applies `VERBOSE` (`e.Raw`) raw/PEM/OpenSSL detail to **both** the verified-chains and peer-certs sections — the flag is set on `certReport` before the first render; don't move it between the two.
- gopls/`staticcheck` flag ~38 "inefficient string concatenation in WriteString" warnings in `api.go`. Pre-existing and accepted style here — don't rewrite report assembly wholesale.
- `ReportOcsp` guards on `len(ocspResponse) > 8`; the `// @UPSTREAM` comment about `Response.Status` is load-bearing: it is a plain `int` `{Good=0|Revoked=1|Unknown=2}` (certificate status), NOT `ocsp.ResponseStatus` (protocol status: success/malformed/...) — never re-cast it into `ResponseStatus`.
- `ReportOcsp` expects the **issuer** cert and binds the staple to the presented leaf via `ocsp.ParseResponseForCert(raw, leaf, issuer)` (`PeerCertificates[0]`): a valid staple for another certificate of the same issuer must be rejected — pinned by `TestReportOcspSerialBinding`. `ThisUpdate`/`NextUpdate` are validated manually (upstream does not); stale responses get `[WARNING] [stale response]` — pinned by `TestReportOcspStale`. Parse failures return `"[tlsinfo] [error] [ocsp] ..."`.
- `ReportConn` passes `PeerCertificates[1]` as issuer, falling back to `[0]` for leaf-only chains.
- `readLine` (starttls.go) accepts a final response line that arrives without its trailing newline (io.EOF with data), caps one line at `_maxLine` (4096) bytes and keeps timeouts as errors — pinned by `TestReadLine`/`TestReadLineTooLong`.
- `starttlsDial` clears the 30s deadline once the TLS handshake succeeds (`conn.SetDeadline(time.Time{})`): the cap bounds dial + negotiation + handshake only, never the connection's remaining lifetime.
- `ReportTlsState` must survive a nil `ConnectionState` (guard → zero-value report); `splitAddr` maps empty/portless/missing-host addresses to `"[none]"` — pinned by tests. `addPort` trims whitespace, returns `""` for empty hosts (never probes localhost), including the `":"`, `":443"` and `"[]:443"` shapes that `net.SplitHostPort` reports as an empty host, and appends the default port after an empty port (`host:`) — pinned by `TestAddCheckPort`.
- **Verified chains stay empty for every tlsinfo-initiated dial** (Go only populates `ConnectionState.VerifiedChains` when `InsecureSkipVerify` is false). The report therefore renders `[none] [chain verification not performed by this connection]` instead of a silently empty section — don't remove that note without adding a real verification pass.
- `ConnectionState.ServerName` is empty for IP-literal targets (Go zeroes SNI for IPs, `hostnameInSNI` in `crypto/tls`) — not a tlsinfo bug; same for plain `tls.Dial`. Test `127.0.0.1` STARTTLS targets accordingly.
- Unbracketed IPv6 literals (`2001:db8::1`) get bracketed by `addPort` before port append; `host:port` with bare IPv6 is ambiguous input (stdlib requires brackets) and fails dial with a clear error.
- go.mod declares `go 1.27.3`; both workflows use `go-version-file: go.mod`, so CI follows the module toolchain. Don't lower go.mod.
- `version()` in `generic.go` hard-codes TLS token labels incl. `[SECURITY ALERT]` verdicts — update both the extended and plain switch tables together.

## Finishing a task (repo owner's standing rule)

1. `gofmt`/`make check`, build, test (if any).
2. Commit: `git add . && git commit -m '<message>'`.
3. Tag patch bump: result is `v0.X.<N+1>` from the latest existing tag.
4. Push commits **and** tag: `git push && git push origin <tag>`.
5. Update this AGENTS.md in the same change when commands/conventions shift.
