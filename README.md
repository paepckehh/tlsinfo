# OVERVIEW
[![Go Reference](https://pkg.go.dev/badge/paepcke.de/tlsinfo.svg)](https://pkg.go.dev/paepcke.de/tlsinfo) [![Go Report Card](https://goreportcard.com/badge/paepcke.de/tlsinfo)](https://goreportcard.com/report/paepcke.de/tlsinfo)

[paepcke.de/tlsinfo](https://paepcke.de/tlsinfo/)

-   tired of remembering all the commandline switches of [openssl|certutil] to analyze an tls session, trust cert chains, ...
-   validated and (clean) export certificate chains, keys, pins, cryptographic states by just entering the hostname
-   get alerts about any anomalies, broken or depricated cryptographic functions
-   100% pure go, minimal(internal-only) imports, use as app or api (see api.go), compatible with certinfo, dnsinfo, ...

# INSTALL

```
go install paepcke.de/tlsinfo/cmd/tlsinfo@latest
```

### DOWNLOAD (prebuild)

[github.com/paepckehh/tlsinfo/releases](https://github.com/paepckehh/tlsinfo/releases)

# SHOWTIME 

## Get a summary of a single host TLS [connection|handshake].

``` Shell
tlsinfo github.com
NET Local Address          : 10.159.67.228
NET Local Port             : 33536
NET Remote Address         : 20.27.177.113
NET Remote Port            : 443
TLS Handshake Finished     : true
TLS Version                : TLS1.3 [0x0304] [OK]
TLS ALPN                   : 
TLS Resumed                : false
TLS Protocol Mutual        : true
TLS Server Name            : github.com
TLS Cipher Suite           : TLS_CHACHA20_POLY1305_SHA256
TLS Uniq ID               
TLS Signed Timestamps     
TLS Verified Cert Chains
TLS Peer Send Certs     

X509 Cert Subject           : [CN=github.com,O=GitHub\, Inc.,L=San Francisco,ST=California,C=US] 
X509 Cert Status            : [VALID] [for the next 90 days]
X509 Cert Signature Algo    : [VALID] [ECDSA-SHA384] 
X509 Cert Public Key        : [VALID] [ECDSA] [prime256v1] 
X509 Cert KeyPin [base64]   : [/3ftdeWqIAONye/CeEQuLGvtlw4MPnQmKgyPLugFbK8=] 
X509 Cert Valid for Host    : [github.com] [www.github.com] 
X509 Cert Key Usage         : [CRITICAL] [Digital Signature] 
X509 Cert Key Usage Ext     : [TLS Web server authentication] [TLS Web client authentication] 
X509 Cert Transparency SCT  : [YES] [RFC6962 SCT] 
X509 CA Authority           : [NO]
X509 Issuer Signature By    : [CN=DigiCert TLS Hybrid ECC SHA384 2020 CA1,O=DigiCert Inc,C=US] 
X509 Issuer Signature State : [FAIL] [x509: certificate signed by unknown authority] 
X509 Issuer URL             : [http://cacerts.digicert.com/DigiCertTLSHybridECCSHA3842020CA1-1.crt] 
X509 Issuer OCSP            : [http://ocsp.digicert.com] 

X509 Cert Subject           : [CN=DigiCert TLS Hybrid ECC SHA384 2020 CA1,O=DigiCert Inc,C=US] 
X509 Cert Status            : [VALID] [for the next 3041 days]
X509 Cert Signature Algo    : [VALID] [SHA384-RSA] 
X509 Cert Public Key        : [VALID] [ECDSA] [secp384r1] 
X509 Cert KeyPin [base64]   : [e0IRz5Tio3GA1Xs4fUVWmH1xHDiH2dMbVtCBSkOIdqM=] 
X509 Cert Key Usage         : [CRITICAL] [Digital Signature] [Certificate Signing] [CRL Signing] 
X509 Cert Key Usage Ext     : [TLS Web server authentication] [TLS Web client authentication] 
X509 CA Authority           : [YES]
X509 CA Allows SubCAs       : [NO] [PathLen:0]
X509 Issuer Signature By    : [CN=DigiCert Global Root CA,OU=www.digicert.com,O=DigiCert Inc,C=US] 
X509 Issuer Signature State : [VALID] [trusted via system trust store]
X509 Issuer URL             : [http://cacerts.digicert.com/DigiCertGlobalRootCA.crt] 
X509 Issuer OCSP            : [http://ocsp.digicert.com] 
[...]
```

## Same but in ascii only non-color mode for post-processing, logging, ...

``` Shell
NO_COLOR=true tlsinfo github.com | grep ... 
[...]
```

## Need full details?

``` Shell
VERBOSE=true tlsinfo github.com 
[...]
```

## Need only the base64 encoded keypin(s) of a host? 

``` Shell
PINONLY=true tlsinfo github.com 
[...]
```

## Fetch, decode, sanitize, clean re-encode a peers certificate

``` Shell
PEMONLY=true tlsinfo github.com > truststore.pem
[..]
```

# API

## Input Objects to Analyze:

-   hostname 
-   net/http/Request
-   crypto/tls/Connection
-   crypto/tls/ConnectionState
-   crypto/ocsp

## Output Format Styles via paepcke.de/reportstyle

-   Plain Text
-   Ansi Color Console
-   HTML
-   Custom \[get wild\]

## TLS state report of a single host 

``` Golang 
package main 

import ( 
	"os" 
	"paepcke.de/tlsinfo"
)

func main() { 
	os.Stdout.Write([]byte(HostReportAnsi("github.com"))) 
}

```

## Get an HTML TLS state report of an client connection within your http handler function

``` Golang
[...]
reportPage := HttpRequestReportHTML(q) // q is normally the server http.Request object within http handler
[...]
```

# DOCS

[pkg.go.dev/paepcke.de/tlsinfo](https://pkg.go.dev/paepcke.de/tlsinfo)

# CONTRIBUTION

Yes, Please! PRs Welcome! 
