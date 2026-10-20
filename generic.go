package tlsinfo

import (
	"net"
	"strings"
	"time"

	"paepcke.de/reportstyle"
)

//
// INTERNAL LITTLE HELPER SECTION
//

// const
const (
	_tcp         = "tcp"
	_sslport     = ":443"
	_none        = "[none]"
	_space       = " "
	_linefeed    = "\n"
	_doublepoint = ":"
	_dialWait    = 30 * time.Second
	_maxLine     = 4096 // cap for one STARTTLS response line, a hostile server must not grow it without bound
)

// build ...
func build(in string, e *reportstyle.Style) string {
	if len(in) > 0 {
		if strings.Contains(in, _linefeed) {
			return e.L3 + in + e.LE
		}
		return e.L2 + in + e.LE
	}
	return e.LE
}

// esc ...
func esc(in string, e *reportstyle.Style) string {
	if e != nil && e.SaniFunc != nil {
		return e.SaniFunc(in)
	}
	return in
}

// styleOr ...
func styleOr(e *reportstyle.Style) *reportstyle.Style {
	if e == nil {
		return reportstyle.StyleText()
	}
	return e
}

// document ...
func document(in string, e *reportstyle.Style) string {
	if e.Start == "" && e.End == "" {
		return in
	}
	return e.Start + in + e.End
}

// splitAddr ...
func splitAddr(addr string) (string, string) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		if addr == "" {
			return _none, _none
		}
		return addr, _none
	}
	if host == "" {
		host = _none
	}
	return host, port
}

// addPort ...
func addPort(host, port string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return "" // let the dialer report a missing address instead of probing localhost
	}
	if h, p, err := net.SplitHostPort(host); err == nil && p != "" {
		return host
	} else if err == nil {
		host = h // strip an empty port (host:) and append the default below
	}
	if strings.Contains(host, _doublepoint) && !strings.HasPrefix(host, "[") {
		return "[" + host + "]" + port // unbracketed ipv6 literal
	}
	return host + port
}

// addCheckPort ...
func addCheckPort(host string) string {
	return addPort(host, _sslport)
}

// version ...
func version(token uint16, extended bool) string {
	if extended {
		switch token {
		case 0x0300:
			return "SSL3.0 [0x0300] [SECURITY ALERT]"
		case 0x0301:
			return "TLS1.0 [0x0301] [SECURITY ALERT]"
		case 0x0302:
			return "TLS1.1 [0x0302] [SECURITY ALERT]"
		case 0x0303:
			return "TLS1.2 [0x0303] [LEGACY FALLBACK]"
		case 0x0304:
			return "TLS1.3 [0x0304] [OK]"
		}
		return "Invalid TLS Version Token"
	}
	switch token {
	case 0x0300:
		return "SSL3.0"
	case 0x0301:
		return "TLS1.0"
	case 0x0302:
		return "TLS1.1"
	case 0x0303:
		return "TLS1.2"
	case 0x0304:
		return "TLS1.3"
	}
	return "Invalid TLS Version Token"
}
