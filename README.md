<div align="center">

# 🔐 tlsinfo

**Know exactly what's on the wire.**

One static binary that talks TLS to anything (web, mail, news, FTP) and tells you what the
handshake, the certificate chain, the key pins and the OCSP staple *actually* look like.

No config files. No daemon. No dependency tree.

[![Go Reference](https://pkg.go.dev/badge/paepcke.de/tlsinfo.svg)](https://pkg.go.dev/paepcke.de/tlsinfo)
[![Go Report Card](https://goreportcard.com/badge/paepcke.de/tlsinfo)](https://goreportcard.com/report/paepcke.de/tlsinfo)
[![Go Version](https://img.shields.io/github/go-mod/go-version/paepckehh/tlsinfo)](go.mod)
[![License](https://img.shields.io/github/license/paepckehh/tlsinfo)](https://github.com/paepckehh/tlsinfo/blob/master/LICENSE)
[![Release](https://img.shields.io/github/v/release/paepckehh/tlsinfo?color=success&label=release)](https://github.com/paepckehh/tlsinfo/releases/latest)
[![built with nix](https://builtwithnix.org/badge.svg)](https://search.nixos.org/packages?channel=unstable&show=tlsinfo&from=0&size=50&sort=relevance&type=packages&query=tlsinfo)

[![Go Build](https://github.com/paepckehh/tlsinfo/actions/workflows/golang.yml/badge.svg)](https://github.com/paepckehh/tlsinfo/actions/workflows/golang.yml)
[![CodeQL](https://github.com/paepckehh/tlsinfo/actions/workflows/codeql.yml/badge.svg)](https://github.com/paepckehh/tlsinfo/actions/workflows/codeql.yml)

[![Stars](https://img.shields.io/github/stars/paepckehh/tlsinfo?style=flat&color=ffd700)](https://github.com/paepckehh/tlsinfo/stargazers)
[![Forks](https://img.shields.io/github/forks/paepckehh/tlsinfo?style=flat)](https://github.com/paepckehh/tlsinfo/network)
[![Issues](https://img.shields.io/github/issues/paepckehh/tlsinfo?style=flat)](https://github.com/paepckehh/tlsinfo/issues)
[![Commit activity](https://img.shields.io/github/commit-activity/m/paepckehh/tlsinfo?style=flat&color=brightgreen)](https://github.com/paepckehh/tlsinfo/commits)

[paepcke.de/tlsinfo](https://paepcke.de/tlsinfo/)

</div>

---

> **TL;DR**
>
> ```shell
> go install paepcke.de/tlsinfo/cmd/tlsinfo@latest
> tlsinfo github.com
> ```
>
> One command. One report. Every TLS fact you were about to dig out of `openssl s_client`.

## Contents

- [Why tlsinfo](#why-tlsinfo)
- [See it in action](#see-it-in-action)
- [Install](#install)
- [Usage](#usage)
- [Library](#library)
- [How it works](#how-it-works)
- [Design promises](#design-promises)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)
- [Citation](#citation)

## Why tlsinfo

TLS is invisible until it isn't. Then you are three terminals deep in `openssl s_client`,
`openssl x509`, a calendar, a pinning spreadsheet and a browser devtools panel, trying to
answer one question: **is this connection what I think it is?**

`tlsinfo` answers it in one shot, for the CLI and for your Go code, using the same engine:

- 🧭 **Handshake truth, no interpretation** - TLS version, cipher suite, ALPN, resumption,
  SCT timestamps and the TLS unique ID. Version labels carry instant `[OK]` /
  `[LEGACY FALLBACK]` / `[SECURITY ALERT]` verdicts.
- 📄 **Every certificate, parsed** - subject, validity window, signature algorithm, public
  key, SANs, chain layout and the SPKI key pin, without a single OpenSSL invocation.
- 🛡️ **OCSP that means something** - the stapled response is verified against the issuer
  *and bound to the presented leaf*. A valid staple for a different certificate is rejected.
  Stale staples get `[WARNING]`, revoked certificates get `[SECURITY ALERT]`.
- 📌 **Pins built for real use** - SPKI base64 pins for trust-on-first-use, even on
  untrusted or self-signed chains, with verification helpers ready for production.
- 🚀 **STARTTLS included** - SMTP, IMAP, POP3, NNTP and FTP upgrades, so the mail and news
  servers nobody remembers to check are one flag away.
- 🎨 **Output for humans and machines** - ANSI color, plain ASCII, HTML (injection-safe),
  or fully custom styles via `reportstyle`, plus raw PEM/OpenSSL detail on demand.
- 🧪 **Zero surprise dependencies** - pure Go, CGO off. Direct imports: the standard library
  plus [`certinfo`](https://pkg.go.dev/paepcke.de/certinfo),
  [`reportstyle`](https://pkg.go.dev/paepcke.de/reportstyle) and
  [`x/crypto`](https://pkg.go.dev/golang.org/x/crypto). Nothing heavier sneaks in.

## See it in action

```console
$ tlsinfo github.com
NET Local Address          : 10.20.0.99
NET Local Port             : 39360
NET Remote Address         : 140.82.121.4
NET Remote Port            : 443
TLS Handshake Finished     : true
TLS Version                : TLS1.3 [0x0304] [OK]
TLS ALPN                   :
TLS Resumed                : false
TLS Server Name            : github.com
TLS Cipher Suite           : TLS_AES_128_GCM_SHA256
TLS Uniq ID
TLS Signed Timestamps
TLS Verified Cert Chains
[none] [chain verification not performed by this connection]
  X509 Cert Subject          : [CN=github.com]
  X509 Cert Status           : [VALID] [for the next 49 days]
  X509 Cert Signature Algo   : [VALID] [ECDSA-SHA256]
  X509 Cert Public Key       : [VALID] [ECDSA] [prime256v1]
  X509 Cert KeyPin [base64]  : [/wiL5vgOLgwED41WS0DNF8QiTBVR/P41Kd163tmFxK0=]
  [...]
```

One report per host. Pass several, or pipe a list:

```shell
tlsinfo github.com paepcke.de
echo github.com | tlsinfo
cat hosts.txt | tlsinfo
```

Want just the pin? `tlsinfo -pin github.com`.

Want the mail server behind port 587? `tlsinfo -starttls smtp smtp.gmail.com:587`.

Want HTML for a dashboard? `tlsinfo -html github.com | your-renderer`.

## Install

```shell
# run it right now
go run paepcke.de/tlsinfo/cmd/tlsinfo@latest github.com

# install it
go install paepcke.de/tlsinfo/cmd/tlsinfo@latest
```

<details>
<summary><strong>Other install options</strong></summary>

Prebuilt binaries for Linux, macOS, Windows and the BSDs (amd64/arm64):
[github.com/paepckehh/tlsinfo/releases](https://github.com/paepckehh/tlsinfo/releases/latest).
`.deb` and `.rpm` packages are published with every release.

NixOS / Nix:

```shell
nix-shell -p tlsinfo
```

```nix
environment.systemPackages = [ pkgs.tlsinfo ];
```

Build from source:

```shell
git clone https://github.com/paepckehh/tlsinfo
cd tlsinfo
make build
./tlsinfo github.com
```

</details>

## Usage

### Command line flags

POSIX conventions, stdlib `flag`, `tlsinfo -h` prints usage with the version.
Every flag has an environment variable fallback for existing scripts
(empty value = off, see [no-color.org](https://no-color.org)):

| Flag           | Environment variable | Effect                                                          |
|----------------|----------------------|-----------------------------------------------------------------|
| `-starttls p`  | `STARTTLS`           | negotiate STARTTLS first: `smtp`, `imap`, `pop3`, `nntp`, `ftp` |
| `-pin`         | `PINONLY`            | print only the base64 SPKI key pin(s)                            |
| `-verbose`     | `VERBOSE`            | add raw / PEM / OpenSSL certificate details                      |
| `-html`        | `HTML`               | HTML output, escaped and ready for a page                        |
| `-no-color`    | `NO_COLOR`           | plain ASCII output, no ANSI colors                               |
| `-version`     | -                    | print the build-time version and exit                            |

Flags go **before** the hosts (`tlsinfo -pin github.com`, not `tlsinfo github.com -pin`).
Piped hosts win when the stream carries any; otherwise the command line is used.

Exit codes: `0` every check succeeded, `1` a host check failed (unreachable, failed
handshake, ...), `2` usage error.

### STARTTLS

Analyze mail and news servers that only speak TLS after an in-band upgrade:

```shell
tlsinfo -starttls smtp  smtp.gmail.com:587
tlsinfo -starttls imap  mail.example.com
tlsinfo -starttls pop3  mail.example.com
tlsinfo -starttls nntp  news.example.com
tlsinfo -starttls ftp   ftp.example.com
```

The protocol name is case- and whitespace-insensitive (`SMTP`, ` smtp ` both work), and the
default port is appended automatically.

### Key pins

```shell
# fetch the base64 SPKI pin of a host
tlsinfo -pin github.com

# works via STARTTLS too
tlsinfo -pin -starttls smtp smtp.gmail.com:587
```

Pin verification lives in the library (`PinVerifyHost`, `PinVerifyStartTLS`), so a pin
becomes a one-line check in your deploy pipeline.

## Library

The CLI is a thin wrapper around a pure Go engine. Import it and get the same report
without shelling out.

```go
package main

import (
	"os"

	"paepcke.de/tlsinfo"
)

func main() {
	os.Stdout.WriteString(tlsinfo.ReportHostText("github.com"))
}
```

Report the clients that hit your own HTTPS endpoint:

```go
// r is the *http.Request inside your handler
report := tlsinfo.ReportHttpRequestHTML(r)
```

Verify a trust-on-first-use pin:

```go
ok := tlsinfo.PinVerifyHost("/wiL5vgOLgwED41WS0DNF8QiTBVR/P41Kd163tmFxK0=", "github.com")
```

Check a mail server through STARTTLS:

```go
report := tlsinfo.ReportStartTLSText("smtp.gmail.com:587", tlsinfo.SMTP)
pin := tlsinfo.PinStartTLS("smtp.gmail.com:587", tlsinfo.SMTP, &tls.Config{})
```

### API

| Function | Input |
|----------|-------|
| `ReportHostText` / `ReportHostHTML` / `ReportHost` | hostname (+ `tls.Config`, `*reportstyle.Style`) |
| `ReportConnText` / `ReportConnHTML` / `ReportConn` | established `*tls.Conn` |
| `ReportTlsStateText` / `ReportTlsStateHTML` / `ReportTlsState` | `*tls.ConnectionState` |
| `ReportHttpRequestText` / `ReportHttpRequestHTML` / `ReportHttpRequest` | server-side `*http.Request` |
| `ReportOcsp` | `*tls.Conn` + issuer `*x509.Certificate` (bound to the leaf, stale responses flagged) |
| `ReportStartTLS` / `ReportStartTLSText` / `ReportStartTLSHTML` | hostname + `smtp`/`imap`/`pop3`/`nntp`/`ftp` |
| `PinHost`, `PinHostWithTLS` | hostname (+ `tls.Config`) |
| `PinStartTLS` | hostname + protocol (+ `tls.Config`) |
| `PinVerifyStartTLS` | key pin + hostname + protocol (+ `tls.Config`) |
| `PinVerifyHost`, `PinVerifyHostWithTLS` | key pin + hostname |
| `PinVerifyConn`, `PinVerifyState` | key pin + `*tls.Conn` / `*tls.ConnectionState` |

Output styles come from [`paepcke.de/reportstyle`](https://pkg.go.dev/paepcke.de/reportstyle):
plain text, ANSI console, HTML, or fully custom. Dynamic values (server name, ALPN, error
text, ...) pass through the style sanitizer, so HTML reports are escaped against injection
and wrapped in the style's `Start`/`End` markers.

Library guarantees worth knowing:

- your `*tls.Config` is **cloned**, never mutated, even though inspection forces
  `InsecureSkipVerify`;
- `nil` styles, connections and requests are tolerated (plain-text report or tagged error,
  never a panic);
- the library never writes to stdout. Output is always the returned string.

## How it works

1. The host is normalized (`:443` appended, bare IPv6 bracketed, empty hosts are rejected
   instead of probing localhost).
2. A TLS connection is opened, or a plaintext one upgraded through the protocol table.
3. `tls.ConnectionState` is walked and certificates are rendered by `certinfo`.
4. The result is assembled with the requested style and sanitized on the way out.

There is no daemon, no cache, no config and no background work. Each invocation is one
connection and one report.

## Design promises

- **Boring dependency tree.** Standard library plus three focused direct packages, and only
  the two transitive modules they require (`x/sys`, `certificate-transparency-go`). No
  framework, no CLI toolkit, no YAML loader.
- **Static binary.** `CGO_ENABLED=0` everywhere, including releases.
- **Offline tests.** The suite spins up loopback TLS and STARTTLS servers; `make test`
  never touches the network.
- **Readable failures.** Errors are embedded in the returned string as
  `[tlsinfo] [error] ...` / `[starttls] [error] ...`, so CLI exit codes and logs stay simple.
- **No surprises in HTML.** Every injected value is escaped through the style sanitizer.

## Documentation

- [pkg.go.dev/paepcke.de/tlsinfo](https://pkg.go.dev/paepcke.de/tlsinfo)
- Machine-readable repo overview for LLMs: [llms.txt](llms.txt)
- Agent/contributor notes: [AGENTS.md](AGENTS.md)
- Found a security issue? See [SECURITY.md](SECURITY.md)

## Contributing

Yes, please! PRs, issues and reproductions are welcome. Start with
[CONTRIBUTING.md](CONTRIBUTING.md), run `make test`, and keep the zero-dependency
philosophy intact.

## License

BSD 3-Clause. See [LICENSE](https://github.com/paepckehh/tlsinfo/blob/master/LICENSE).

## Citation

```bibtex
@misc{tlsinfo,
  author = {Michael Paepcke},
  title = {Tool to analyze and troubleshoot TLS connections (app/lib/api)},
  year = {2022},
  publisher = {GitHub},
  journal = {GitHub repository},
  howpublished = {\url{https://paepcke.de/tlsinfo}}
}
```
