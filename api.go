// package tlsinfo reports tls connection parameter
package tlsinfo

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net/http"
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
	t.InsecureSkipVerify = true // skip here to get  tls.ConnectionState()
	conn, err := tls.Dial(_tcp, addCheckPort(host), t)
	if err != nil {
		return "DEBUG:" + err.Error()
	}
	defer conn.Close()
	return ReportConn(conn, e)
}

// ReportConn ...
func ReportConn(conn *tls.Conn, e *reportstyle.Style) string {
	state := conn.ConnectionState()
	localIP := strings.Split(conn.LocalAddr().String(), _doublepoint)
	remoteIP := strings.Split(conn.RemoteAddr().String(), _doublepoint)
	var s strings.Builder
	if len(localIP) > 1 {
		s.WriteString(e.L1 + "NET Local Address         " + e.L2 + localIP[0] + e.LE)
		s.WriteString(e.L1 + "NET Local Port            " + e.L2 + localIP[1] + e.LE)
	}
	if len(remoteIP) > 1 {
		s.WriteString(e.L1 + "NET Remote Address        " + e.L2 + remoteIP[0] + e.LE)
		s.WriteString(e.L1 + "NET Remote Port           " + e.L2 + remoteIP[1] + e.LE)
	}
	if msg := ReportOcsp(conn, state.PeerCertificates[1]); len(msg) > 0 {
		s.WriteString(e.L1 + "TLS OCSP Status           " + build(msg, e))
	}
	s.WriteString(ReportTlsState(&state, e))
	return s.String()
}

// ReportHttpRequest ...
func ReportHttpRequest(q *http.Request, e *reportstyle.Style) string {
	state := q.TLS
	remoteIP := strings.Split(q.RemoteAddr, _doublepoint)
	var s strings.Builder
	s.WriteString(e.L1 + "NET Remote address        " + e.L2 + remoteIP[0] + e.LE)
	s.WriteString(e.L1 + "NET Remote port           " + e.L2 + remoteIP[1] + e.LE)
	s.WriteString(e.L1 + "HTTP Protocol             " + e.L2 + q.Proto + e.LE)
	s.WriteString(e.L1 + "HTTP Transfer Encoding    " + e.L2 + strings.Join(q.TransferEncoding, _space) + e.LE)
	s.WriteString(ReportTlsState(state, e))
	return s.String()
}

// ReportTlsState ...
func ReportTlsState(state *tls.ConnectionState, e *reportstyle.Style) string {
	certReport := &certinfo.Report{Summary: true, Style: e}
	var ts string
	if len(state.SignedCertificateTimestamps) > 0 {
		ts = string(bytes.Join(state.SignedCertificateTimestamps, []byte(_linefeed)))
	}
	var s strings.Builder
	s.WriteString(e.L1 + "TLS Handshake Finished    " + e.L2 + valid(state.HandshakeComplete) + e.LE)
	s.WriteString(e.L1 + "TLS Version               " + e.L2 + version(state.Version, true) + e.LE)
	s.WriteString(e.L1 + "TLS ALPN                  " + e.L2 + state.NegotiatedProtocol + e.LE)
	s.WriteString(e.L1 + "TLS Resumed               " + e.L2 + valid(state.DidResume) + e.LE)
	s.WriteString(e.L1 + "TLS Server Name           " + e.L2 + state.ServerName + e.LE)
	s.WriteString(e.L1 + "TLS Cipher Suite          " + e.L2 + tls.CipherSuiteName(state.CipherSuite) + e.LE)
	//nolint:all - keep as informative point, besides linter correct security concerns
	s.WriteString(e.L1 + "TLS Uniq ID               " + build(hex.EncodeToString(state.TLSUnique), e))
	s.WriteString(e.L1 + "TLS Signed Timestamps     " + build(ts, e))
	s.WriteString(e.L1 + "TLS Verified Cert Chains\n" + build(certinfo.CertStores(state.VerifiedChains, certReport), e))
	if e.Raw {
		certReport.OpenSSL, certReport.PEM = true, true
	}
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
		// @UPSTREAM golang.org/x/ocsp, type Response struct Status is not type int but type ResponseStatus
		return ocsp.ResponseStatus(r.Status).String()
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
	conn, err := tls.Dial(_tcp, target, tlsconfig)
	if err != nil {
		return "[certinfo] [error] [connect] " + target + " -> " + err.Error()
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) > 0 {
		return certinfo.KeyPinBase64(certs[0])
	}
	return "[certinfo] [error] [keypin] [no certificates found] :" + target
}
