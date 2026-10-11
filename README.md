<div align="center">

# tlsinfo

**Analyze TLS connections from the terminal — or from your own Go code.**

[![Go Reference](https://pkg.go.dev/badge/paepcke.de/tlsinfo.svg)](https://pkg.go.dev/paepcke.de/tlsinfo)
[![Go Report Card](https://goreportcard.com/badge/paepcke.de/tlsinfo)](https://goreportcard.com/report/paepcke.de/tlsinfo)
[![License](https://img.shields.io/github/license/paepckehh/tlsinfo)](https://github.com/paepckehh/tlsinfo/blob/master/LICENSE)
[![Release](https://img.shields.io/github/v/release/paepckehh/tlsinfo)](https://github.com/paepckehh/tlsinfo/releases/latest)
[![Go Build](https://github.com/paepckehh/tlsinfo/actions/workflows/golang.yml/badge.svg)](https://github.com/paepckehh/tlsinfo/actions/workflows/golang.yml)
[![Lint](https://github.com/paepckehh/tlsinfo/actions/workflows/golangci-lint.yml/badge.svg)](https://github.com/paepckehh/tlsinfo/actions/workflows/golangci-lint.yml)
[![built with nix](https://builtwithnix.org/badge.svg)](https://search.nixos.org/packages?channel=unstable&show=tlsinfo&from=0&size=50&sort=relevance&type=packages&query=tlsinfo)

[paepcke.de/tlsinfo](https://paepcke.de/tlsinfo/)

</div>

---

## Why

Tired of remembering all the command-line switches of `openssl s_client` / `certutil` to
analyze a TLS session or a trust chain? Just enter the hostname.

- Validates, parses and reports certificate chains, keys, pins, cryptographic states
- Handshake state: TLS version, cipher suite, ALPN, resumption, SCT timestamps
- OCSP status (stapled responses), with `[SECURITY ALERT]` verdicts on revoked certificates
- Key pins (SPKI, base64) to build or verify trust-on-first-use pinning
- Alerts about anomalies, broken or deprecated cryptographic functions
- 100% pure Go — stdlib + `paepcke.de/certinfo` + `paepcke.de/reportstyle` + `golang.org/x/crypto` only
- Use as CLI **or** as library ([API](#api)); compatible with `certinfo`, `dnsinfo`, ...

## ⚡️ Quickstart

```shell
# run via go
go run paepcke.de/tlsinfo/cmd/tlsinfo@latest github.com

# install via go
go install paepcke.de/tlsinfo/cmd/tlsinfo@latest
```

Prebuilt binaries: [github.com/paepckehh/tlsinfo/releases](https://github.com/paepckehh/tlsinfo/releases)

NixOS:

```shell
nix-shell -p tlsinfo
```

```nix
environment.systemPackages = [ pkgs.tlsinfo ];
```

## 📖 Usage

```shell
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

Multiple hosts, or a list piped via stdin — one report per host:

```shell
tlsinfo github.com paepcke.de
echo github.com | tlsinfo
cat hosts.txt | tlsinfo
```

### Environment Variables

| Variable  | Effect                                                                   |
|-----------|--------------------------------------------------------------------------|
| `NO_COLOR`| plain ASCII output, no ANSI colors (post-processing, logging, ...)       |
| `VERBOSE` | add raw / PEM / OpenSSL certificate details                              |
| `HTML`     | HTML output (for web pages, reports, ...)                                |
| `PINONLY` | print only the base64 SPKI key pin(s) of the host(s)                    |
| `PEMONLY` | reserved, currently inactive                                            |

### Library

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

### API

| Function                                     | Input                                    |
|----------------------------------------------|-------------------------------------------|
| `ReportHostText` / `ReportHostHTML` / `ReportHost` | hostname (+ `tls.Config`, `*reportstyle.Style`) |
| `ReportConnText` / `ReportConnHTML` / `ReportConn` | established `*tls.Conn`                |
| `ReportTlsStateText` / `ReportTlsStateHTML` / `ReportTlsState` | `*tls.ConnectionState`       |
| `ReportHttpRequestText` / `ReportHttpRequestHTML` / `ReportHttpRequest` | server-side `*http.Request` |
| `ReportOcsp`                                 | `*tls.Conn` + issuer `*x509.Certificate`  |
| `PinHost`, `PinHostWithTLS`                  | hostname (+ `tls.Config`)                 |
| `PinVerifyHost`, `PinVerifyHostWithTLS`      | key pin + hostname                        |
| `PinVerifyConn`, `PinVerifyState`            | key pin + `*tls.Conn` / `*tls.ConnectionState` |

Output format styles (via [`paepcke.de/reportstyle`](https://pkg.go.dev/paepcke.de/reportstyle)):
plain text, ANSI color console, HTML, raw, or fully custom.

## 📚 Documentation

[pkg.go.dev/paepcke.de/tlsinfo](https://pkg.go.dev/paepcke.de/tlsinfo)

## 🛡 License

This project is licensed under the terms of the `BSD 3-Clause License`.
See [LICENSE](https://github.com/paepckehh/tlsinfo/blob/master/LICENSE) for details.

## 📃 Citation

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

## 🤝 Contribution

Yes, please! PRs welcome! See [CONTRIBUTING.md](CONTRIBUTING.md).