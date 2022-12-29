package tlsinfo

import (
	"strings"

	"paepcke.de/reportstyle"
)

//
// INTERNAL LITTLE HELPER SECTION
//

// const
const (
	_tcp         = "tcp"
	_tcp4        = "tcp4"
	_tcp6        = "tcp6"
	_sslport     = ":443"
	_none        = "[none]"
	_space       = " "
	_linefeed    = "\n"
	_doublepoint = ":"
)

// valid ...
func valid(state bool) string {
	if state {
		return "true"
	}
	return "false"
}

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

// addCheckPort ...
func addCheckPort(host string) string {
	if len(strings.Split(host, _doublepoint)) > 1 {
		return host
	}
	return host + _sslport
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
