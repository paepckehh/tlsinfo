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
