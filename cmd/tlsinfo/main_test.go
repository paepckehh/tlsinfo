package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"paepcke.de/reportstyle"
)

// TestIsEnv ...
func TestIsEnv(t *testing.T) {
	t.Setenv("TLSINFO_TEST_SET", "yes")
	if !isEnv("TLSINFO_TEST_SET") {
		t.Error("isEnv() = false, want true for set environment variable")
	}
	if isEnv("TLSINFO_TEST_UNSET") {
		t.Error("isEnv() = true, want false for unset environment variable")
	}
	t.Setenv("TLSINFO_TEST_EMPTY", "")
	if isEnv("TLSINFO_TEST_EMPTY") {
		t.Error("isEnv() = true, want false for empty environment variable")
	}
}

// TestReportErrorDetection ...
func TestReportErrorDetection(t *testing.T) {
	if !report("host.invalid", "", false, reportstyle.StyleText()) {
		t.Error("report() = false for unresolvable host, want true to signal a failed check")
	}
}

// TestVersionDefault ...
func TestVersionDefault(t *testing.T) {
	if _version == "" {
		t.Error("_version must never be empty, falls back to dev when not injected at build time")
	}
}

// TestBuildVersion ...
func TestBuildVersion(t *testing.T) {
	if got := buildVersion(); got == "" {
		t.Error("buildVersion() must never be empty")
	}
	old := _version
	defer func() { _version = old }()
	_version = "v0.0.0-test"
	if got := buildVersion(); got != "v0.0.0-test" {
		t.Errorf("buildVersion() = %q, want the injected tag", got)
	}
	_version = "dev"
	if got := buildVersion(); got == "" {
		t.Error("buildVersion() must fall back to a non-empty value without an injected tag")
	}
}

// TestGetPipe ...
func TestGetPipe(t *testing.T) {
	content := "github.com\npaepcke.de\n"
	old := os.Stdin
	os.Stdin = stdin(t, content)
	defer func() { os.Stdin = old }()
	if got := getPipe(); got != content {
		t.Errorf("getPipe() = %q, want %q", got, content)
	}
}

// TestPipeHosts ...
func TestPipeHosts(t *testing.T) {
	old := os.Stdin
	os.Stdin = stdin(t, "github.com\r\n\n paepcke.de\n")
	defer func() { os.Stdin = old }()
	want := []string{"github.com", "paepcke.de"}
	if got := pipeHosts(); !reflect.DeepEqual(got, want) {
		t.Errorf("pipeHosts() = %v, want %v", got, want)
	}
}

// TestWithNewline ...
func TestWithNewline(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want string
	}{
		{"", "\n"},
		{"pin", "pin\n"},
		{"report\n", "report\n"},
	}
	for _, tt := range tests {
		if got := withNewline(tt.in); got != tt.want {
			t.Errorf("withNewline(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestIsErr ...
func TestIsErr(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want bool
	}{
		{"[tlsinfo] [error] [connect] x", true},
		{"[starttls] [error] [connect] x", true},
		{"NET Remote Address        : 127.0.0.1\nTLS OCSP Status           : [error] in cert text\n", false},
		{"Good [OK]\n", false},
	}
	for _, tt := range tests {
		if got := isErr(tt.in); got != tt.want {
			t.Errorf("isErr(%q) = %t, want %t", tt.in, got, tt.want)
		}
	}
}

// TestCheckArgs ...
func TestCheckArgs(t *testing.T) {
	t.Parallel()
	if err := checkArgs([]string{"github.com", "paepcke.de"}); err != nil {
		t.Errorf("checkArgs(hosts) unexpected error: %s", err.Error())
	}
	if err := checkArgs([]string{"github.com", "-pin"}); err == nil {
		t.Error("checkArgs() must reject a flag after a host")
	}
}

// TestInputHosts ...
func TestInputHosts(t *testing.T) {
	old := os.Stdin
	os.Stdin = stdin(t, "github.com\n")
	defer func() { os.Stdin = old }()
	if got := inputHosts([]string{"paepcke.de"}); !reflect.DeepEqual(got, []string{"github.com"}) {
		t.Errorf("inputHosts() = %v, want the piped host", got)
	}
	os.Stdin = stdin(t, "\n")
	if got := inputHosts([]string{"paepcke.de"}); !reflect.DeepEqual(got, []string{"paepcke.de"}) {
		t.Errorf("inputHosts() = %v, want the command line fallback for empty input", got)
	}
}

// stdin ...
func stdin(t *testing.T, content string) *os.File {
	t.Helper()
	file, err := os.Create(filepath.Join(t.TempDir(), "pipe"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = file.Close()
	})
	if _, err := file.WriteString(content); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	return file
}
