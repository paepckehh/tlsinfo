package tlsinfo

import (
	"testing"

	"paepcke.de/reportstyle"
)

// testStyle ...
func testStyle() *reportstyle.Style {
	return &reportstyle.Style{L1: "<l1>", L2: "<l2>", L3: "<l3>", LE: "<le>"}
}

// TestBuild ...
func TestBuild(t *testing.T) {
	t.Parallel()
	e := testStyle()
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty input", "", "<le>"},
		{"single line", "ok", "<l2>ok<le>"},
		{"multi line", "a\nb", "<l3>a\nb<le>"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := build(tt.in, e); got != tt.want {
				t.Errorf("build(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestSplitAddr ...
func TestSplitAddr(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		addr string
		host string
		port string
	}{
		{"ipv4", "127.0.0.1:443", "127.0.0.1", "443"},
		{"ipv6", "[2001:db8::1]:4433", "2001:db8::1", "4433"},
		{"missing port", "127.0.0.1", "127.0.0.1", "[none]"},
		{"empty address", "", "[none]", "[none]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			host, port := splitAddr(tt.addr)
			if host != tt.host || port != tt.port {
				t.Errorf("splitAddr(%q) = (%q, %q), want (%q, %q)", tt.addr, host, port, tt.host, tt.port)
			}
		})
	}
}

// TestAddCheckPort ...
func TestAddCheckPort(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		host string
		want string
	}{
		{"appends default port", "github.com", "github.com:443"},
		{"keeps explicit port", "github.com:8443", "github.com:8443"},
		{"keeps ip port", "127.0.0.1:9", "127.0.0.1:9"},
		{"appends port to bracketed ipv6", "[2001:db8::1]", "[2001:db8::1]:443"},
		{"appends port to bare ipv6 literal", "2001:db8::1", "[2001:db8::1]:443"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := addCheckPort(tt.host); got != tt.want {
				t.Errorf("addCheckPort(%q) = %q, want %q", tt.host, got, tt.want)
			}
		})
	}
}

// TestVersion ...
func TestVersion(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		token    uint16
		extended bool
		want     string
	}{
		{"ssl30 plain", 0x0300, false, "SSL3.0"},
		{"tls10 extended alert", 0x0301, true, "TLS1.0 [0x0301] [SECURITY ALERT]"},
		{"tls11 plain", 0x0302, false, "TLS1.1"},
		{"tls12 extended legacy", 0x0303, true, "TLS1.2 [0x0303] [LEGACY FALLBACK]"},
		{"tls13 extended ok", 0x0304, true, "TLS1.3 [0x0304] [OK]"},
		{"unknown plain", 0x1234, false, "Invalid TLS Version Token"},
		{"unknown extended", 0x1234, true, "Invalid TLS Version Token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := version(tt.token, tt.extended); got != tt.want {
				t.Errorf("version(0x%04x, %t) = %q, want %q", tt.token, tt.extended, got, tt.want)
			}
		})
	}
}
