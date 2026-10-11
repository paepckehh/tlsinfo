// package main ...
package main

// import
import (
	"crypto/tls"
	"io"
	"log"
	"os"
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
	_pemonly  = "PEMONLY"
	_pinonly  = "PINONLY"
	_starttls = "STARTTLS"
	_verbose  = "VERBOSE"
)

// main ...
func main() {
	style := reportstyle.StyleAnsi()
	if isEnv(_noColor) {
		style = reportstyle.StyleText()
	}
	if isEnv(_html) {
		style = reportstyle.StyleHTML()
	}
	if isEnv(_verbose) {
		style.Raw = true
	}
	switch {
	case isPipe():
		for _, host := range pipeHosts() {
			report(host, style)
		}
	case isOsArgs():
		for _, host := range os.Args[1:] {
			report(host, style)
		}
	default:
		log.Fatal(_app + _err + "no pipe or input parameter found, example: tlsinfo github.com")
	}
}

//
// LITTLE GENERIC HELPER SECTION
//

// report ...
func report(host string, style *reportstyle.Style) {
	proto := os.Getenv(_starttls)
	switch {
	case isEnv(_pinonly):
		if proto != "" {
			out(tlsinfo.PinStartTLS(host, proto, &tls.Config{}))
			return
		}
		out(tlsinfo.PinHost(host))
	case isEnv(_pemonly):
		// out(tlsinfo.PemHost(host))
	case proto != "":
		out(tlsinfo.ReportStartTLS(host, proto, &tls.Config{}, style))
	default:
		out(tlsinfo.ReportHost(host, &tls.Config{}, style))
	}
}

// out ...
func out(msg string) {
	if _, err := os.Stdout.Write([]byte(msg)); err != nil {
		panic("unrecoverable error, unable to write stdout")
	}
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
		log.Fatal(_app + _err + "reading data from pipe")
	}
	return string(pipe)
}

// isOsArgs ...
func isOsArgs() bool {
	return len(os.Args) > 1
}

// isEnv ...
func isEnv(in string) bool {
	_, ok := os.LookupEnv(in)
	return ok
}
