package tlsinfo

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

//
// STARTTLS BACKEND - PLAINTEXT PROTOCOL UPGRADE TO TLS
//

// STARTTLS protocol identifiers
const (
	SMTP = "smtp"
	IMAP = "imap"
	POP3 = "pop3"
	NNTP = "nntp"
	FTP  = "ftp"
)

// const
const (
	_crlf = "\r\n"
)

// starttlsDef ...
type starttlsDef struct {
	port     string
	sequence [][]string
}

// default plaintext ports plus negotiation sequences per protocol: send command, want response prefix
var _starttlsProtocols = map[string]starttlsDef{
	SMTP: {port: ":587", sequence: [][]string{{"", "220"}, {"EHLO tlsinfo", "250"}, {"STARTTLS", "220"}}},
	IMAP: {port: ":143", sequence: [][]string{{"", "* OK"}, {"A001 STARTTLS", "A001 OK"}}},
	POP3: {port: ":110", sequence: [][]string{{"", "+OK"}, {"STLS", "+OK"}}},
	NNTP: {port: ":119", sequence: [][]string{{"", "20"}, {"STARTTLS", "382"}}},
	FTP:  {port: ":21", sequence: [][]string{{"", "220"}, {"AUTH TLS", "234"}}},
}

// addStarttlsPort ...
func addStarttlsPort(proto, host string) (string, error) {
	def, ok := _starttlsProtocols[proto]
	if !ok {
		return "", starttlsUnsupported(proto)
	}
	return addPort(host, def.port), nil
}

// starttlsUnsupported ...
func starttlsUnsupported(proto string) error {
	return fmt.Errorf("[starttls] [error] [unsupported protocol: %q] [supported: %s, %s, %s, %s, %s]", proto, SMTP, IMAP, POP3, NNTP, FTP)
}

// starttlsDial ...
func starttlsDial(proto, host string, t *tls.Config) (*tls.Conn, error) {
	proto = strings.ToLower(proto)
	if t == nil {
		t = &tls.Config{}
	}
	t.InsecureSkipVerify = true // skip here to get tls.ConnectionState()
	addr, err := addStarttlsPort(proto, host)
	if err != nil {
		return nil, err
	}
	raw, err := net.DialTimeout(_tcp, addr, _dialWait)
	if err != nil {
		return nil, err
	}
	if err := raw.SetDeadline(time.Now().Add(_dialWait)); err != nil {
		_ = raw.Close()
		return nil, err
	}
	if err := starttlsUpgrade(proto, raw); err != nil {
		_ = raw.Close()
		return nil, err
	}
	if t.ServerName == "" {
		if serverName, _, err := net.SplitHostPort(addr); err == nil {
			t.ServerName = serverName
		}
	}
	if err := raw.SetDeadline(time.Now().Add(_dialWait)); err != nil { // fresh window for the TLS handshake itself
		_ = raw.Close()
		return nil, err
	}
	conn := tls.Client(raw, t)
	if err := conn.Handshake(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// starttlsUpgrade ...
func starttlsUpgrade(proto string, conn net.Conn) error {
	def, ok := _starttlsProtocols[proto]
	if !ok {
		return starttlsUnsupported(proto)
	}
	r := bufio.NewReader(conn)
	for _, step := range def.sequence {
		if err := reply(r, conn, step[0], step[1]); err != nil {
			return err
		}
	}
	return nil
}

// reply ...
func reply(r *bufio.Reader, conn net.Conn, send, want string) error {
	if send != "" {
		if _, err := conn.Write([]byte(send + _crlf)); err != nil {
			return fmt.Errorf("[starttls] [error] [unable to send: %q] %s", send, err.Error())
		}
	}
	line, err := readLine(r)
	if err != nil {
		return fmt.Errorf("[starttls] [error] [unable to read response of: %q] %s", send, err.Error())
	}
	for {
		if !strings.HasPrefix(line, want) {
			return fmt.Errorf("[starttls] [error] [unexpected response: %q] [want prefix: %q]", line, want)
		}
		if len(line) <= len(want) || line[len(want)] != '-' {
			return nil
		}
		if line, err = readLine(r); err != nil {
			return fmt.Errorf("[starttls] [error] [unable to read response of: %q] %s", send, err.Error())
		}
	}
}

// readLine ...
func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString(_linefeed[0])
	return strings.TrimRight(line, _crlf), err
}
