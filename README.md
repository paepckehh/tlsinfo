<div align="center">

# 🔐 tlsinfo

**TLS analysis in one command — or one function call.**

Handshake state, certificate chains, key pins, OCSP status and crypto hygiene for any host.
A tiny CLI **and** a pure Go library. No flags, no config files, no bloat.

[![Go Reference](https://pkg.go.dev/badge/paepcke.de/tlsinfo.svg)](https://pkg.go.dev/paepcke.de/tlsinfo)
[![Go Report Card](https://goreportcard.com/badge/paepcke.de/tlsinfo)](https://goreportcard.com/report/paepcke.de/tlsinfo)
[![Go Version](https://img.shields.io/github/go-mod/go-version/paepckehh/tlsinfo)](go.mod)
[![License](https://img.shields.io/github/license/paepckehh/tlsinfo)](https://github.com/paepckehh/tlsinfo/blob/master/LICENSE)
[![Release](https://img.shields.io/github/v/release/paepckehh/tlsinfo?color=success&label=release)](https://github.com/paepckehh/tlsinfo/releases/latest)
[![built with nix](https://builtwithnix.org/badge.svg)](https://search.nixos.org/packages?channel=unstable&show=tlsinfo&from=0&size=50&sort=relevance&type=packages&query=tlsinfo)

[![Go Build](https://github.com/paepckehh/tlsinfo/actions/workflows/golang.yml/badge.svg)](https://github.com/paepckehh/tlsinfo/actions/workflows/golang.yml)
[![Lint](https://github.com/paepckehh/tlsinfo/actions/workflows/golangci-lint.yml/badge.svg)](https://github.com/paepckehh/tlsinfo/actions/workflows/golangci-lint.yml)
[![CodeQL](https://github.com/paepckehh/tlsinfo/actions/workflows/codeql.yml/badge.svg)](https://github.com/paepckehh/tlsinfo/actions/workflows/codeql.yml)

[![Stars](https://img.shields.io/github/stars/paepckehh/tlsinfo?style=flat&color=ffd700)](https://github.com/paepckehh/tlsinfo/stargazers)
[![Forks](https://img.shields.io/github/forks/paepckehh/tlsinfo?style=flat)](https://github.com/paepckehh/tlsinfo/network)
[![Issues](https://img.shields.io/github/issues/paepckehh/tlsinfo?style=flat)](https://github.com/paepckehh/tlsinfo/issues)
[![Commit activity](https://img.shields.io/github/commit-activity/m/paepckehh/tlsinfo?style=flat&color=brightgreen)](https://github.com/paepckehh/tlsinfo/commits)

[paepcke.de/tlsinfo](https://paepcke.de/tlsinfo/)

</div>

---

## Contents

- [Features](#features)
- [Quickstart](#quickstart)
- [Usage](#usage)
- [Library](#library)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)

## Features

- 📄 **Full chain analysis** — validates, parses and reports certificate chains, keys, pins and cryptographic states
- 🤝 **Handshake state** — TLS version, cipher suite, ALPN, resumption, SCT timestamps, with instant `[SECURITY ALERT]` / `[OK]` verdicts
- 🚀 **STARTTLS testing** — upgrade plaintext connections and analyze the TLS layer (SMTP, IMAP, POP3, NNTP, FTP)
- 📌 **Key pins** — SPKI base64 pins to build or verify trust-on-first-use (TOFU) pinning, even on untrusted or self-signed chains
- 🛡️ **OCSP status** — stapled responses parsed and verified against the issuer, revoked certificates flagged as `[SECURITY ALERT]`
- 🧪 **Works everywhere** — 100% pure Go: stdlib + `paepcke.de/certinfo` + `paepcke.de/reportstyle` + `golang.org/x/crypto`, nothing else
- 🎨 **Output your way** — ANSI console, plain ASCII, HTML, raw/PEM/OpenSSL detail, or fully custom styles
- 🔌 **CLI *or* library** — same core, [library API](#library), compatible with `certinfo`, `dnsinfo`, ...

## Quickstart

```shell
# try it instantly
go run paepcke.de/tlsinfo/cmd/tlsinfo@latest github.com

# install it
go install paepcke.de/tlsinfo/cmd/tlsinfo@latest
```

<details>
<summary>Other install options</summary>

Prebuilt binaries for every platform: [releases](https://github.com/paepckehh/tlsinfo/releases/latest)

NixOS:

```shell
nix-shell -p tlsinfo
```

```nix
environment.systemPackages = [ pkgs.tlsinfo ];
```

</details>

## Usage

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

  X509 Cert Subject          : [CN=github.com]
  X509 Cert Status           : [VALID] [for the next 49 days]
  X509 Cert Signature Algo   : [VALID] [ECDSA-SHA256]
  X509 Cert Public Key       : [VALID] [ECDSA] [prime256v1]
  X509 Cert KeyPin [base64]  : [/wiL5vgOLgwED41WS0DNF8QiTBVR/P41Kd163tmFxK0=]
  [...]
```

One report per host — pass multiple hosts, or pipe a list via stdin:

```shell
tlsinfo github.com paepcke.de
echo github.com | tlsinfo
cat hosts.txt | tlsinfo
```

### STARTTLS

Analyze mail or news servers that speak TLS only after an in-band upgrade:

```shell
STARTTLS=smtp tlsinfo smtp.gmail.com:587
STARTTLS=imap tlsinfo mail.example.com
```

### Key pins

```shell
# fetch the base64 SPKI key pin of a host (TOFU first use)
PINONLY=1 tlsinfo github.com

# works via STARTTLS too
PINONLY=1 STARTTLS=smtp tlsinfo smtp.gmail.com:587
```

### Environment variables

The CLI is configured entirely via environment variables (empty value = off, see [no-color.org](https://no-color.org)):

| Variable  | Effect                                                                       |
|-----------|------------------------------------------------------------------------------|
| `NO_COLOR` | plain ASCII output, no ANSI colors (post-processing, logging, ...)          |
| `VERBOSE`  | add raw / PEM / OpenSSL certificate details                                  |
| `HTML`     | HTML output (for web pages, reports, ...)                                    |
| `PINONLY`  | print only the base64 SPKI key pin(s) of the host(s)                          |
| `PEMONLY`  | reserved, currently inactive                                                 |
| `STARTTLS` | test STARTTLS instead of implicit TLS: `smtp`, `imap`, `pop3`, `nntp`, `ftp` |

## Library

Full TLS state report of a host:

```go
package main

import (
	"os"

	"paepcke.de/tlsinfo"
)

func main() {
	os.Stdout.Write([]byte(tlsinfo.ReportHostText("github.com")))
}
```

Report your own clients from inside an HTTP handler:

```go
// r is the *http.Request within your http handler
report := tlsinfo.ReportHttpRequestHTML(r)
```

Verify a host key pin (SPKI trust-on-first-use):

```go
ok := tlsinfo.PinVerifyHost("/wiL5vgOLgwED41WS0DNF8QiTBVR/P41Kd163tmFxK0=", "github.com")
```

Test a mail server via STARTTLS (SMTP, IMAP, POP3, NNTP, FTP):

```go
report := tlsinfo.ReportStartTLSText("smtp.gmail.com:587", tlsinfo.SMTP)
pin := tlsinfo.PinStartTLS("smtp.gmail.com:587", tlsinfo.SMTP, &tls.Config{})
```

### API

| Function                                     | Input                                     |
|----------------------------------------------|-------------------------------------------|
| `ReportHostText` / `ReportHostHTML` / `ReportHost` | hostname (+ `tls.Config`, `*reportstyle.Style`) |
| `ReportConnText` / `ReportConnHTML` / `ReportConn` | established `*tls.Conn`                  |
| `ReportTlsStateText` / `ReportTlsStateHTML` / `ReportTlsState` | `*tls.ConnectionState`          |
| `ReportHttpRequestText` / `ReportHttpRequestHTML` / `ReportHttpRequest` | server-side `*http.Request` |
| `ReportOcsp`                                 | `*tls.Conn` + issuer `*x509.Certificate` |
| `ReportStartTLS` / `ReportStartTLSText` / `ReportStartTLSHTML` | hostname + `smtp`/`imap`/`pop3`/`nntp`/`ftp` |
| `PinHost`, `PinHostWithTLS`                  | hostname (+ `tls.Config`)                 |
| `PinStartTLS`                                | hostname + protocol (+ `tls.Config`)      |
| `PinVerifyStartTLS`                          | key pin + hostname + protocol (+ `tls.Config`) |
| `PinVerifyHost`, `PinVerifyHostWithTLS`      | key pin + hostname                        |
| `PinVerifyConn`, `PinVerifyState`            | key pin + `*tls.Conn` / `*tls.ConnectionState` |

Output format styles (via [`paepcke.de/reportstyle`](https://pkg.go.dev/paepcke.de/reportstyle)):
plain text, ANSI color console, HTML, raw, or fully custom.

## Documentation

- [pkg.go.dev/paepcke.de/tlsinfo](https://pkg.go.dev/paepcke.de/tlsinfo)
- Machine-readable repo overview for LLMs: [llms.txt](llms.txt)
- Found a security issue? See [SECURITY.md](SECURITY.md)

## Contributing

Yes, please! PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for the ground rules.

## License

This project is licensed under the terms of the `BSD 3-Clause License`.
See [LICENSE](https://github.com/paepckehh/tlsinfo/blob/master/LICENSE) for details.

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