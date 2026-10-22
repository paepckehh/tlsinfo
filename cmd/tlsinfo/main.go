// package main ...
package main

// import
import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"

	"paepcke.de/reportstyle"
	"paepcke.de/tlsinfo"
)

// const
const (
	_app      = "[tlsinfo] "
	_err      = "[error] "
	_html     = "HTML"
	_noColor  = "NO_COLOR"
	_pinonly  = "PINONLY"
	_starttls = "STARTTLS"
	_verbose  = "VERBOSE"
)

// _version tracks the release tag, injected at build time via
// -ldflags "-X main._version=v0.X.Y" (see Makefile and .goreleaser.yml)
var _version = "dev"

// main ...
func main() {
	flag.Usage = usage
	proto := flag.String("starttls", os.Getenv(_starttls), "negotiate STARTTLS before the TLS handshake: smtp, imap, pop3, nntp, ftp (env "+_starttls+")")
	pin := flag.Bool("pin", isEnv(_pinonly), "key pin output only (env "+_pinonly+")")
	html := flag.Bool("html", isEnv(_html), "HTML output (env "+_html+")")
	noColor := flag.Bool("no-color", isEnv(_noColor), "plain text output (env "+_noColor+")")
	verbose := flag.Bool("verbose", isEnv(_verbose), "raw PEM and OpenSSL certificate detail (env "+_verbose+")")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(buildVersion())
		return
	}
	fmt.Fprintf(os.Stderr, "tlsinfo %s\n", buildVersion())
	style := reportstyle.StyleAnsi()
	switch {
	case *html:
		style = reportstyle.StyleHTML()
	case *noColor:
		style = reportstyle.StyleText()
	}
	if *verbose {
		style.Raw = true
	}
	var failed bool
	hosts := inputHosts(flag.Args())
	if len(hosts) == 0 {
		usage()
		os.Exit(2)
	}
	if err := checkArgs(hosts); err != nil {
		fmt.Fprintln(os.Stderr, _app+_err+err.Error())
		usage()
		os.Exit(2)
	}
	for _, host := range hosts {
		failed = report(host, *proto, *pin, style) || failed
	}
	if failed {
		os.Exit(1)
	}
}

//
// LITTLE GENERIC HELPER SECTION
//

// buildVersion ... build-time tag when injected, module version for `go install`, dev otherwise
func buildVersion() string {
	if _version != "" && _version != "dev" {
		return _version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return _version
}

// usage ...
func usage() {
	fmt.Fprintf(os.Stderr, "tlsinfo %s - report TLS connection and certificate details\n\n", buildVersion())
	fmt.Fprintf(os.Stderr, "usage: tlsinfo [flags] host [host...]\n       hosts are read from stdin when piped\n\nflags:\n")
	flag.PrintDefaults()
}

// report ...
func report(host, proto string, pin bool, style *reportstyle.Style) bool {
	var msg string
	switch {
	case pin && proto != "":
		msg = tlsinfo.PinStartTLS(host, proto, &tls.Config{})
	case pin:
		msg = tlsinfo.PinHost(host)
	case proto != "":
		msg = tlsinfo.ReportStartTLS(host, proto, &tls.Config{}, style)
	default:
		msg = tlsinfo.ReportHost(host, &tls.Config{}, style)
	}
	out(msg)
	return isErr(msg)
}

// isErr ...
func isErr(msg string) bool {
	return strings.HasPrefix(msg, "[tlsinfo] [error]") || strings.HasPrefix(msg, "[starttls] [error]")
}

// inputHosts ... piped input wins when it carries hosts, otherwise the command line is used
func inputHosts(args []string) []string {
	if isPipe() {
		if hosts := pipeHosts(); len(hosts) > 0 {
			return hosts
		}
	}
	return args
}

// checkArgs ...
func checkArgs(hosts []string) error {
	for _, host := range hosts {
		if strings.HasPrefix(host, "-") {
			return fmt.Errorf("flags must precede hosts: %q", host)
		}
	}
	return nil
}

// out ...
func out(msg string) {
	if _, err := os.Stdout.WriteString(withNewline(msg)); err != nil {
		panic("unrecoverable error, unable to write stdout")
	}
}

// withNewline ...
func withNewline(msg string) string {
	if strings.HasSuffix(msg, "\n") {
		return msg
	}
	return msg + "\n"
}

// isPipe ...
func isPipe() bool {
	out, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return out.Mode()&os.ModeCharDevice == 0
}

// pipeHosts ...
func pipeHosts() []string {
	return strings.Fields(getPipe())
}

// getPipe ...
func getPipe() string {
	pipe, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, _app+_err+"reading data from pipe")
		os.Exit(1)
	}
	return string(pipe)
}

// isEnv ...
func isEnv(in string) bool {
	val, ok := os.LookupEnv(in)
	return ok && val != "" // empty value means off, see https://no-color.org
}
