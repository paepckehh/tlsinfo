package tlsinfo

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
	"paepcke.de/certinfo"
	"paepcke.de/reportstyle"
)

// testCA ...
func testCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "tlsinfo test ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return ca, key
}

// testLeaf ...
func testLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "tlsinfo test leaf"},
		DNSNames:     []string{"example.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, key.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return leaf, key
}

// testServer ...
func testServer(t *testing.T) (addr string, ca, leaf *x509.Certificate) {
	t.Helper()
	ca, caKey := testCA(t)
	leaf, leafKey := testLeaf(t, ca, caKey)
	staple, err := ocsp.CreateResponse(ca, ca, ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: leaf.SerialNumber,
		ThisUpdate:   time.Now(),
		NextUpdate:   time.Now().Add(time.Hour),
	}, caKey)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := tls.Listen(_tcp, "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{leaf.Raw, ca.Raw},
			PrivateKey:  leafKey,
			OCSPStaple:  staple,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
	})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn *tls.Conn) {
				defer func() { _ = conn.Close() }()
				_ = conn.Handshake()
			}(conn.(*tls.Conn))
		}
	}()
	return listener.Addr().String(), ca, leaf
}

// testTlsState ...
func testTlsState(t *testing.T, leaf, ca *x509.Certificate) *tls.ConnectionState {
	t.Helper()
	return &tls.ConnectionState{
		HandshakeComplete:           true,
		Version:                     tls.VersionTLS13,
		NegotiatedProtocol:          "h2",
		ServerName:                  "example.test",
		CipherSuite:                 tls.TLS_AES_128_GCM_SHA256,
		PeerCertificates:            []*x509.Certificate{leaf},
		VerifiedChains:              [][]*x509.Certificate{{leaf, ca}},
		TLSUnique:                   []byte("uniq"),
		SignedCertificateTimestamps: [][]byte{[]byte("sct-a"), []byte("sct-b")},
	}
}

// TestReportTlsState ...
func TestReportTlsState(t *testing.T) {
	ca, caKey := testCA(t)
	leaf, _ := testLeaf(t, ca, caKey)
	out := ReportTlsState(testTlsState(t, leaf, ca), reportstyle.StyleText())
	for _, sub := range []string{
		"TLS Handshake Finished", "true",
		"TLS Version", "TLS1.3 [0x0304] [OK]",
		"TLS ALPN", "h2",
		"TLS Resumed", "false",
		"TLS Server Name", "example.test",
		"TLS Cipher Suite", "TLS_AES_128_GCM_SHA256",
		"TLS Uniq ID", "756e6971",
		"TLS Signed Timestamps", "sct-a\nsct-b",
		"TLS Verified Cert Chains", "tlsinfo test leaf",
		"TLS Peer Send Certs", "tlsinfo test ca",
	} {
		if !strings.Contains(out, sub) {
			t.Errorf("ReportTlsState() output missing %q", sub)
		}
	}
	if out := ReportTlsState(nil, reportstyle.StyleText()); !strings.Contains(out, "TLS Version") {
		t.Errorf("ReportTlsState(nil) must not panic and still render a report, got: %q", out)
	}
}

// TestReportHttpRequest ...
func TestReportHttpRequest(t *testing.T) {
	t.Parallel()
	ca, caKey := testCA(t)
	leaf, _ := testLeaf(t, ca, caKey)
	tests := []struct {
		name string
		out  string
		want []string
	}{
		{
			"full state",
			ReportHttpRequestText(&http.Request{Proto: "HTTP/1.1", RemoteAddr: "192.0.2.1:1234", TLS: testTlsState(t, leaf, ca)}),
			[]string{"192.0.2.1", "1234", "HTTP Protocol", "HTTP/1.1", "TLS Version", "TLS1.3 [0x0304] [OK]"},
		},
		{
			"ipv6 remote",
			ReportHttpRequestText(&http.Request{Proto: "HTTP/1.1", RemoteAddr: "[2001:db8::2]:443", TLS: testTlsState(t, leaf, ca)}),
			[]string{"2001:db8::2", "443"},
		},
		{
			"no tls state",
			ReportHttpRequestText(&http.Request{Proto: "HTTP/1.1", RemoteAddr: "192.0.2.1:1234"}),
			[]string{"HTTP Protocol", "TLS Version"},
		},
		{
			"empty remote addr",
			ReportHttpRequestText(&http.Request{Proto: "HTTP/1.1"}),
			[]string{"[none]", "HTTP Protocol"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			for _, sub := range tt.want {
				if !strings.Contains(tt.out, sub) {
					t.Errorf("ReportHttpRequest() output missing %q", sub)
				}
			}
		})
	}
}

// TestReportConn ...
func TestReportConn(t *testing.T) {
	addr, _, _ := testServer(t)
	conn, err := tls.Dial(_tcp, addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	out := ReportConn(conn, reportstyle.StyleText())
	for _, sub := range []string{
		"NET Local Address", "NET Local Port",
		"NET Remote Address", "NET Remote Port", "127.0.0.1",
		"TLS OCSP Status", "Good [OK]",
		"TLS Version", "TLS1.3 [0x0304] [OK]",
	} {
		if !strings.Contains(out, sub) {
			t.Errorf("ReportConn() output missing %q", sub)
		}
	}
}

// TestReportHost ...
func TestReportHost(t *testing.T) {
	addr, _, _ := testServer(t)
	if out := ReportHost(addr, &tls.Config{}, reportstyle.StyleText()); !strings.Contains(out, "TLS Handshake Finished") {
		t.Errorf("ReportHost() output missing %q:\n%s", "TLS Handshake Finished", out)
	}
	if out := ReportHost(addr, nil, reportstyle.StyleText()); !strings.Contains(out, "TLS Handshake Finished") {
		t.Errorf("ReportHost(nil config) must not panic and still render a report, got:\n%s", out)
	}
	if out := ReportHost("127.0.0.1:1", &tls.Config{}, reportstyle.StyleText()); !strings.Contains(out, "[tlsinfo] [error] [connect]") {
		t.Errorf("ReportHost() unreachable host must embed the connect error, got:\n%s", out)
	}
}

// TestReportOcsp ...
func TestReportOcsp(t *testing.T) {
	addr, ca, leaf := testServer(t)
	conn, err := tls.Dial(_tcp, addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if got := ReportOcsp(conn, ca); got != "Good [OK]" {
		t.Errorf("ReportOcsp(conn, issuer) = %q, want %q", got, "Good [OK]")
	}
	if got := ReportOcsp(conn, leaf); got == "Good [OK]" || !strings.Contains(got, "[error]") {
		t.Errorf("ReportOcsp(conn, leaf) must embed a tagged error after the issuer signature check fails, got %q", got)
	}
	if got := ReportOcsp(conn, nil); got == "" || got == "Good [OK]" {
		t.Errorf("ReportOcsp(conn, nil) must return the raw hex response, got %q", got)
	}
}

// TestPinVerifyState ...
func TestPinVerifyState(t *testing.T) {
	t.Parallel()
	ca, caKey := testCA(t)
	leaf, _ := testLeaf(t, ca, caKey)
	state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
	pin := certinfo.KeyPinBase64(leaf)
	if !PinVerifyState(pin, state) {
		t.Error("PinVerifyState() = false, want true for matching key pin")
	}
	if PinVerifyState("nope", state) {
		t.Error("PinVerifyState() = true, want false for mismatched key pin")
	}
	if PinVerifyState(pin, &tls.ConnectionState{}) {
		t.Error("PinVerifyState() = true, want false for empty connection state")
	}
}

// TestPinHostWithTLS ...
func TestPinHostWithTLS(t *testing.T) {
	addr, _, leaf := testServer(t)
	want := certinfo.KeyPinBase64(leaf)
	if got := PinHostWithTLS(addr, &tls.Config{InsecureSkipVerify: true}); got != want {
		t.Errorf("PinHostWithTLS() = %q, want %q", got, want)
	}
	if got := PinHost(addr); got != want {
		t.Errorf("PinHost() = %q, want %q: trust-on-first-use must pin untrusted chains", got, want)
	}
	if !PinVerifyHost(want, addr) {
		t.Error("PinVerifyHost() = false, want true for matching key pin")
	}
	if !PinVerifyHostWithTLS(want, addr, &tls.Config{InsecureSkipVerify: true}) {
		t.Error("PinVerifyHostWithTLS() = false, want true for matching key pin")
	}
	if PinVerifyHostWithTLS("nope", addr, &tls.Config{InsecureSkipVerify: true}) {
		t.Error("PinVerifyHostWithTLS() = true, want false for mismatched key pin")
	}
}
