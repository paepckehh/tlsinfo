package tlsinfo

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"testing"

	"paepcke.de/certinfo"
	"paepcke.de/reportstyle"
)

// TestAddStarttlsPort ...
func TestAddStarttlsPort(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		proto string
		host  string
		want  string
	}{
		{"smtp default port", SMTP, "mail.example.test", "mail.example.test:587"},
		{"imap default port", IMAP, "mail.example.test", "mail.example.test:143"},
		{"pop3 default port", POP3, "mail.example.test", "mail.example.test:110"},
		{"nntp default port", NNTP, "news.example.test", "news.example.test:119"},
		{"ftp default port", FTP, "ftp.example.test", "ftp.example.test:21"},
		{"explicit port kept", SMTP, "mail.example.test:25", "mail.example.test:25"},
		{"bare ipv6 literal bracketed", SMTP, "2001:db8::1", "[2001:db8::1]:587"},
		{"bracketed ipv6 kept", IMAP, "[2001:db8::1]:143", "[2001:db8::1]:143"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := addStarttlsPort(tt.proto, tt.host)
			if err != nil {
				t.Fatalf("addStarttlsPort(%q, %q) unexpected error: %s", tt.proto, tt.host, err.Error())
			}
			if got != tt.want {
				t.Errorf("addStarttlsPort(%q, %q) = %q, want %q", tt.proto, tt.host, got, tt.want)
			}
		})
	}
	t.Run("unsupported protocol", func(t *testing.T) {
		t.Parallel()
		if _, err := addStarttlsPort("telnet", "mail.example.test"); err == nil {
			t.Error("addStarttlsPort(telnet) must return an unsupported protocol error")
		}
	})
}

// TestReadLine ...
func TestReadLine(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	go func() {
		_, _ = io.WriteString(server, "+OK ready") // final line without newline, then close
		_ = server.Close()
	}()
	line, err := readLine(bufio.NewReader(client))
	if err != nil || line != "+OK ready" {
		t.Errorf("readLine() = (%q, %v), want (%q, nil)", line, err, "+OK ready")
	}
}

// TestReadLineTooLong ...
func TestReadLineTooLong(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	go func() {
		_, _ = io.WriteString(server, strings.Repeat("a", _maxLine+1)+_crlf)
	}()
	if _, err := readLine(bufio.NewReader(client)); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("readLine() error = %v, want an overlong line error", err)
	}
}

// TestStarttlsUpgrade ...
func TestStarttlsUpgrade(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		proto    string
		greeting string
		replies  map[string]string
		wantErr  string
	}{
		{"smtp happy path", SMTP, "220 mail.example.test ESMTP\r\n", map[string]string{
			"EHLO tlsinfo": "250-mail.example.test\r\n250 STARTTLS\r\n",
			"STARTTLS":     "220 Go ahead\r\n",
		}, ""},
		{"imap happy path", IMAP, "* OK IMAP4rev1 ready\r\n", map[string]string{
			"A001 STARTTLS": "A001 OK Begin TLS negotiation now\r\n",
		}, ""},
		{"pop3 happy path", POP3, "+OK POP3 server ready\r\n", map[string]string{
			"STLS": "+OK Begin TLS negotiation now\r\n",
		}, ""},
		{"nntp happy path", NNTP, "201 NNTP server ready posting prohibited\r\n", map[string]string{
			"STARTTLS": "382 TLS available\r\n",
		}, ""},
		{"ftp happy path", FTP, "220 FTP server ready\r\n", map[string]string{
			"AUTH TLS": "234 AUTH TLS successful\r\n",
		}, ""},
		{"smtp multiline ehlo", SMTP, "220 mail.example.test ESMTP\r\n", map[string]string{
			"EHLO tlsinfo": "250-mail\r\n250-PIPELINING\r\n250 STARTTLS\r\n",
			"STARTTLS":     "220 Go ahead\r\n",
		}, ""},
		{"smtp ehlo refused", SMTP, "220 mail.example.test ESMTP\r\n", map[string]string{
			"EHLO tlsinfo": "550 nope\r\n",
		}, "unexpected response"},
		{"smtp starttls refused", SMTP, "220 mail.example.test ESMTP\r\n", map[string]string{
			"EHLO tlsinfo": "250 mail\r\n",
			"STARTTLS":     "454 TLS not available\r\n",
		}, "unexpected response"},
		{"imap starttls refused", IMAP, "* OK ready\r\n", map[string]string{
			"A001 STARTTLS": "A001 NO\r\n",
		}, "unexpected response"},
		{"pop3 greeting refused", POP3, "-ERR go away\r\n", nil, "unexpected response"},
		{"smtp greeting refused", SMTP, "554 go away\r\n", nil, "unexpected response"},
		{"unsupported protocol", "xmpp", "", nil, "unsupported protocol"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			client, server := net.Pipe()
			t.Cleanup(func() {
				_ = client.Close()
				_ = server.Close()
			})
			go func() {
				r := bufio.NewReader(server)
				if _, err := io.WriteString(server, tt.greeting); err != nil {
					return
				}
				for {
					cmd, err := readLine(r)
					if err != nil {
						return
					}
					resp, ok := tt.replies[cmd]
					if !ok {
						return
					}
					if _, err := io.WriteString(server, resp); err != nil {
						return
					}
				}
			}()
			err := starttlsUpgrade(tt.proto, client)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("starttlsUpgrade(%q) unexpected error: %s", tt.proto, err.Error())
				}
				return
			}
			if err == nil {
				t.Fatalf("starttlsUpgrade(%q) = nil, want error containing %q", tt.proto, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("starttlsUpgrade(%q) = %q, want error containing %q", tt.proto, err.Error(), tt.wantErr)
			}
		})
	}
}

// TestReportStartTLS ...
func TestReportStartTLS(t *testing.T) {
	ca, caKey := testCA(t)
	leaf, leafKey := testLeaf(t, ca, caKey)
	listener, err := net.Listen(_tcp, "127.0.0.1:0")
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
			go func(raw net.Conn) {
				defer func() { _ = raw.Close() }()
				r := bufio.NewReader(raw)
				if _, err := io.WriteString(raw, "220 mail.example.test ESMTP\r\n"); err != nil {
					return
				}
				if _, err := readLine(r); err != nil { // EHLO
					return
				}
				if _, err := io.WriteString(raw, "250-mail.example.test\r\n250 STARTTLS\r\n"); err != nil {
					return
				}
				if _, err := readLine(r); err != nil { // STARTTLS
					return
				}
				if _, err := io.WriteString(raw, "220 Go ahead\r\n"); err != nil {
					return
				}
				server := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{{
					Certificate: [][]byte{leaf.Raw},
					PrivateKey:  leafKey,
				}}})
				_ = server.Handshake()
			}(conn)
		}
	}()
	addr := listener.Addr().String()
	out := ReportStartTLS(addr, SMTP, &tls.Config{}, reportstyle.StyleText())
	for _, sub := range []string{"TLS Handshake Finished", "true", "TLS Version", "TLS1.3", "TLS Server Name", "127.0.0.1"} {
		if !strings.Contains(out, sub) {
			t.Errorf("ReportStartTLS() output missing %q", sub)
		}
	}
	if out := ReportStartTLS(addr, "SMTP", &tls.Config{}, reportstyle.StyleText()); strings.Contains(out, "[error]") { // protocol identifiers are case-insensitive
		t.Errorf("ReportStartTLS(SMTP uppercase) = %q, want a finished handshake", out)
	}
	if out := ReportStartTLS(addr, " smtp ", &tls.Config{}, reportstyle.StyleText()); strings.Contains(out, "[error]") { // and whitespace tolerant
		t.Errorf("ReportStartTLS(whitespace padded) = %q, want a finished handshake", out)
	}
	cfg := &tls.Config{}
	if out := ReportStartTLS(addr, SMTP, cfg, reportstyle.StyleText()); strings.Contains(out, "[error]") {
		t.Fatalf("ReportStartTLS() = %q, want a report", out)
	}
	if cfg.InsecureSkipVerify {
		t.Error("ReportStartTLS() mutated the caller's tls.Config")
	}
	pin := certinfo.KeyPinBase64(leaf)
	if got := PinStartTLS(addr, SMTP, &tls.Config{}); got != pin {
		t.Errorf("PinStartTLS() = %q, want %q", got, pin)
	}
	if !PinVerifyStartTLS(pin, addr, SMTP, &tls.Config{}) {
		t.Error("PinVerifyStartTLS() = false, want true for matching key pin")
	}
	if PinVerifyStartTLS("nope", addr, SMTP, &tls.Config{}) {
		t.Error("PinVerifyStartTLS() = true, want false for mismatched key pin")
	}
	out = ReportStartTLS(addr, "telnet", &tls.Config{}, reportstyle.StyleText())
	if !strings.Contains(out, "[starttls] [error]") {
		t.Errorf("ReportStartTLS() unsupported protocol must report an error, got:\n%s", out)
	}
	if n := strings.Count(out, "[starttls] [error]"); n != 1 {
		t.Errorf("ReportStartTLS() error must be tagged exactly once, got %d tags:\n%s", n, out)
	}
	if got := PinStartTLS(addr, "telnet", nil); strings.Count(got, "[starttls] [error]") != 1 {
		t.Errorf("PinStartTLS() unsupported protocol must be tagged exactly once, got:\n%s", got)
	}
}
