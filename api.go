// package tlsinfo reports tls connection parameter
package tlsinfo

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"golang.org/x/crypto/ocsp"
	"paepcke.de/certinfo"
	"paepcke.de/reportstyle"
)

// ExtCheckURLs for direct usage, just add a domainname to url
var ExtCheckURLs = []string{
	"https://www.ssllabs.com/ssltest/analyze.html?d=",
	"https://cryptcheck.fr/https/",
	"https://observatory.mozilla.org/analyze/",
}

//
// SIMPLE API - ASCII REPORTER
//

// ReportHostText ...
func ReportHostText(host string) string {
	return ReportHost(host, &tls.Config{}, reportstyle.StyleText())
}

// ReportConnText ...
func ReportConnText(conn *tls.Conn) string {
	return ReportConn(conn, reportstyle.StyleText())
}

// ReportTlsStateText ...
func ReportTlsStateText(state *tls.ConnectionState) string {
	return ReportTlsState(state, reportstyle.StyleText())
}

// ReportHttpRequestText ...
func ReportHttpRequestText(q *http.Request) string {
	return ReportHttpRequest(q, reportstyle.StyleText())
}

//
// SIMPLE API - HTML REPORTER
//

// ReportHostHTML ...
func ReportHostHTML(host string) string {
	return ReportHost(host, &tls.Config{}, reportstyle.StyleHTML())
}

// ReportHttpRequestHTML ...
func ReportHttpRequestHTML(q *http.Request) string {
	return ReportHttpRequest(q, reportstyle.StyleHTML())
}

// ReportConnHTML ...
func ReportConnHTML(conn *tls.Conn) string {
	return ReportConn(conn, reportstyle.StyleHTML())
}

// ReportTlsStateHTML ...
func ReportTlsStateHTML(state *tls.ConnectionState) string {
	return ReportTlsState(state, reportstyle.StyleHTML())
}

//
// SIMPLE API - LITTLE HELPER
//

// PinHost ...
func PinHost(host string) string {
	return PinHostWithTLS(host, &tls.Config{})
}

// PinVerifyHost ...
func PinVerifyHost(keyPin, host string) bool {
	return PinVerifyHostWithTLS(keyPin, host, &tls.Config{})
}

// PinVerifyConn ...
func PinVerifyConn(keyPin string, conn *tls.Conn) bool {
	state := conn.ConnectionState()
	return PinVerifyState(keyPin, &state)
}

// PinVerifyState ...
func PinVerifyState(keyPin string, state *tls.ConnectionState) bool {
	if len(state.PeerCertificates) > 0 {
		if keyPin == certinfo.KeyPinBase64(state.PeerCertificates[0]) {
			return true
		}
	}
	return false
}

//
// GENERIC BACKEND
//

// ReportHost ...
func ReportHost(host string, t *tls.Config, e *reportstyle.Style) string {
	if t == nil {
		t = &tls.Config{}
	}
	t.InsecureSkipVerify = true // skip here to get  tls.ConnectionState()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: _dialWait}, _tcp, addCheckPort(host), t)
	if err != nil {
		return "[tlsinfo] [error] [connect] " + host + " -> " + err.Error()
	}
	defer func() {
		if err := conn.Close(); err != nil {
			fmt.Printf("[tlsinfo] [error] during connection close: %s", err.Error())
		}
	}()
	return ReportConn(conn, e)
}

// ReportConn ...
func ReportConn(conn *tls.Conn, e *reportstyle.Style) string {
	state := conn.ConnectionState()
	localHost, localPort := splitAddr(conn.LocalAddr().String())
	remoteHost, remotePort := splitAddr(conn.RemoteAddr().String())
	var s strings.Builder
	s.WriteString(e.L1 + "NET Local Address         " + e.L2 + localHost + e.LE)
	s.WriteString(e.L1 + "NET Local Port            " + e.L2 + localPort + e.LE)
	s.WriteString(e.L1 + "NET Remote Address        " + e.L2 + remoteHost + e.LE)
	s.WriteString(e.L1 + "NET Remote Port           " + e.L2 + remotePort + e.LE)
	if len(state.PeerCertificates) > 0 {
		issuer := state.PeerCertificates[0]
		if len(state.PeerCertificates) > 1 {
			issuer = state.PeerCertificates[1]
		}
		if msg := ReportOcsp(conn, issuer); len(msg) > 0 {
			s.WriteString(e.L1 + "TLS OCSP Status           " + build(msg, e))
		}
	}
	s.WriteString(ReportTlsState(&state, e))
	return s.String()
}

// ReportHttpRequest ...
func ReportHttpRequest(q *http.Request, e *reportstyle.Style) string {
	remoteHost, remotePort := splitAddr(q.RemoteAddr)
	var s strings.Builder
	s.WriteString(e.L1 + "NET Remote address        " + e.L2 + remoteHost + e.LE)
	s.WriteString(e.L1 + "NET Remote port           " + e.L2 + remotePort + e.LE)
	s.WriteString(e.L1 + "HTTP Protocol             " + e.L2 + q.Proto + e.LE)
	s.WriteString(e.L1 + "HTTP Transfer Encoding    " + e.L2 + strings.Join(q.TransferEncoding, _space) + e.LE)
	s.WriteString(ReportTlsState(q.TLS, e))
	return s.String()
}

// ReportTlsState ...
func ReportTlsState(state *tls.ConnectionState, e *reportstyle.Style) string {
	if state == nil {
		state = &tls.ConnectionState{}
	}
	certReport := &certinfo.Report{Summary: true, Style: e}
	if e.Raw {
		certReport.OpenSSL, certReport.PEM = true, true // VERBOSE adds raw PEM / OpenSSL detail to both cert sections
	}
	var ts string
	if len(state.SignedCertificateTimestamps) > 0 {
		ts = string(bytes.Join(state.SignedCertificateTimestamps, []byte(_linefeed)))
	}
	var s strings.Builder
	s.WriteString(e.L1 + "TLS Handshake Finished    " + e.L2 + strconv.FormatBool(state.HandshakeComplete) + e.LE)
	s.WriteString(e.L1 + "TLS Version               " + e.L2 + version(state.Version, true) + e.LE)
	s.WriteString(e.L1 + "TLS ALPN                  " + e.L2 + state.NegotiatedProtocol + e.LE)
	s.WriteString(e.L1 + "TLS Resumed               " + e.L2 + strconv.FormatBool(state.DidResume) + e.LE)
	s.WriteString(e.L1 + "TLS Server Name           " + e.L2 + state.ServerName + e.LE)
	s.WriteString(e.L1 + "TLS Cipher Suite          " + e.L2 + tls.CipherSuiteName(state.CipherSuite) + e.LE)
	//nolint:all - keep as informative point, besides linter correct security concerns
	s.WriteString(e.L1 + "TLS Uniq ID               " + build(hex.EncodeToString(state.TLSUnique), e))
	s.WriteString(e.L1 + "TLS Signed Timestamps     " + build(ts, e))
	s.WriteString(e.L1 + "TLS Verified Cert Chains\n" + build(certinfo.CertStores(state.VerifiedChains, certReport), e))
	s.WriteString(e.L1 + "TLS Peer Send Certs     \n" + build(certinfo.CertStore(state.PeerCertificates, certReport), e))
	return s.String()
}

// ReportOcsp ...
func ReportOcsp(conn *tls.Conn, issuerCert *x509.Certificate) string {
	ocspResponse := conn.OCSPResponse()
	if len(ocspResponse) > 8 && issuerCert != nil {
		r, err := ocsp.ParseResponse(ocspResponse, issuerCert)
		if err != nil {
			return err.Error()
		}
		// @UPSTREAM golang.org/x/crypto/ocsp: Response.Status is plain int {Good=0|Revoked=1|Unknown=2}, NOT type ResponseStatus (success/malformed/...)
		switch r.Status {
		case ocsp.Good:
			return "Good [OK]"
		case ocsp.Revoked:
			return "Revoked [SECURITY ALERT]"
		case ocsp.Unknown:
			return "Unknown [WARNING]"
		}
		return "Invalid OCSP Status Token"
	}
	return hex.EncodeToString(ocspResponse)
}

// PinVerifyHostWithTLS ...
func PinVerifyHostWithTLS(keyPin, host string, tlsconfig *tls.Config) bool {
	return keyPin == PinHostWithTLS(host, tlsconfig)
}

// PinHostWithTLS ...
func PinHostWithTLS(host string, tlsconfig *tls.Config) string {
	target := addCheckPort(host)
	if tlsconfig == nil {
		tlsconfig = &tls.Config{}
	}
	tlsconfig.InsecureSkipVerify = true // skip here to pin keys trust-on-first-use, even on untrusted chains
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: _dialWait}, _tcp, target, tlsconfig)
	if err != nil {
		return "[tlsinfo] [error] [connect] " + target + " -> " + err.Error()
	}
	defer func() {
		if err := conn.Close(); err != nil {
			fmt.Printf("[tlsinfo] [error] during connection close: %s: %s", target, err.Error())
		}
	}()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) > 0 {
		return certinfo.KeyPinBase64(certs[0])
	}
	return "[tlsinfo] [error] [keypin] [no certificates found] " + target
}

//
// SIMPLE API - STARTTLS REPORTER
//

// ReportStartTLSText ...
func ReportStartTLSText(host, protocol string) string {
	return ReportStartTLS(host, protocol, &tls.Config{}, reportstyle.StyleText())
}

// ReportStartTLSHTML ...
func ReportStartTLSHTML(host, protocol string) string {
	return ReportStartTLS(host, protocol, &tls.Config{}, reportstyle.StyleHTML())
}

// PinStartTLS ...
func PinStartTLS(host, protocol string, t *tls.Config) string {
	conn, err := starttlsDial(protocol, host, t)
	if err != nil {
		return "[starttls] [error] [connect] " + host + " -> " + err.Error()
	}
	defer func() {
		if err := conn.Close(); err != nil {
			fmt.Printf("[starttls] [error] during connection close: %s", err.Error())
		}
	}()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) > 0 {
		return certinfo.KeyPinBase64(certs[0])
	}
	return "[starttls] [error] [keypin] [no certificates found] " + host
}

// PinVerifyStartTLS ...
func PinVerifyStartTLS(keyPin, host, protocol string, t *tls.Config) bool {
	return keyPin == PinStartTLS(host, protocol, t)
}

//
// GENERIC BACKEND - STARTTLS
//

// ReportStartTLS ...
func ReportStartTLS(host, protocol string, t *tls.Config, e *reportstyle.Style) string {
	conn, err := starttlsDial(protocol, host, t)
	if err != nil {
		return "[starttls] [error] [connect] " + host + " -> " + err.Error()
	}
	defer func() {
		if err := conn.Close(); err != nil {
			fmt.Printf("[starttls] [error] during connection close: %s", err.Error())
		}
	}()
	return ReportConn(conn, e)
}
