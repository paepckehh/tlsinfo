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
	_crlf         = "\r\n"
	_starttlsWait = 30 * time.Second
)

// default plaintext ports per protocol
var _starttlsPort = map[string]string{
	SMTP: ":587",
	IMAP: ":143",
	POP3: ":110",
	NNTP: ":119",
	FTP:  ":21",
}

// plaintext negotiation sequences per protocol: send command, want response prefix
var _starttlsSequence = map[string][][]string{
	SMTP: {{"", "220"}, {"EHLO tlsinfo", "250"}, {"STARTTLS", "220"}},
	IMAP: {{"", "* OK"}, {"A001 STARTTLS", "A001 OK"}},
	POP3: {{"", "+OK"}, {"STLS", "+OK"}},
	NNTP: {{"", "20"}, {"STARTTLS", "382"}},
	FTP:  {{"", "220"}, {"AUTH TLS", "234"}},
}

// addStarttlsPort ...
func addStarttlsPort(proto, host string) (string, error) {
	port, ok := _starttlsPort[proto]
	if !ok {
		return "", fmt.Errorf("[starttls] [error] [unsupported protocol: %q] [supported: %s, %s, %s, %s, %s]", proto, SMTP, IMAP, POP3, NNTP, FTP)
	}
	return addPort(host, port), nil
}

// starttlsDial ...
func starttlsDial(proto, host string, t *tls.Config) (*tls.Conn, error) {
	if t == nil {
		t = &tls.Config{}
	}
	t.InsecureSkipVerify = true // skip here to get tls.ConnectionState()
	addr, err := addStarttlsPort(proto, host)
	if err != nil {
		return nil, err
	}
	raw, err := net.Dial(_tcp, addr)
	if err != nil {
		return nil, err
	}
	if err := raw.SetDeadline(time.Now().Add(_starttlsWait)); err != nil {
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
	conn := tls.Client(raw, t)
	if err := conn.Handshake(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// starttlsUpgrade ...
func starttlsUpgrade(proto string, conn net.Conn) error {
	seq, ok := _starttlsSequence[proto]
	if !ok {
		return fmt.Errorf("[starttls] [error] [unsupported protocol: %q] [supported: %s, %s, %s, %s, %s]", proto, SMTP, IMAP, POP3, NNTP, FTP)
	}
	r := bufio.NewReader(conn)
	for _, step := range seq {
		if _, err := reply(r, conn, step[0], step[1]); err != nil {
			return err
		}
	}
	return nil
}

// reply ...
func reply(r *bufio.Reader, conn net.Conn, send, want string) (string, error) {
	if send != "" {
		if _, err := conn.Write([]byte(send + _crlf)); err != nil {
			return "", fmt.Errorf("[starttls] [error] [unable to send: %q] %s", send, err.Error())
		}
	}
	line, err := readLine(r)
	if err != nil {
		return "", fmt.Errorf("[starttls] [error] [unable to read response of: %q] %s", send, err.Error())
	}
	for {
		if !strings.HasPrefix(line, want) {
			return line, fmt.Errorf("[starttls] [error] [unexpected response: %q] [want prefix: %q]", line, want)
		}
		if len(line) <= len(want) || line[len(want)] != '-' {
			return line, nil
		}
		if line, err = readLine(r); err != nil {
			return line, fmt.Errorf("[starttls] [error] [unable to read response of: %q] %s", send, err.Error())
		}
	}
}

// readLine ...
func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString(_linefeed[0])
	return strings.TrimRight(line, _crlf), err
}
