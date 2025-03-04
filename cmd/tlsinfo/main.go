// package main ...
package main

// import
import (
	"crypto/tls"
	"io"
	"log"
	"os"
	"syscall"

	"paepcke.de/reportstyle"
	"paepcke.de/tlsinfo"
)

// const
const (
	_app      = "[tlsinfo] "
	_err      = "[error] "
	_html     = "HTML"
	_noColor  = "NO_COLOR"
	_verbose  = "VERBOSE"
	_pemonly  = "PEMONLY"
	_pinonly  = "PINONLY"
	_linefeed = "\n"
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
		out(tlsinfo.ReportHost(getPipe(), &tls.Config{}, style))
	case isOsArgs():
		for i := 1; i < len(os.Args); i++ {
			switch {
			case isEnv(_pinonly):
				out(tlsinfo.PinHost(os.Args[i]))
				continue
			case isEnv(_pemonly):
				// out(tlsinfo.PemHost(os.Args[i]))
				continue
			}
			out(tlsinfo.ReportHost(os.Args[i], &tls.Config{}, style))
		}
	default:
		log.Fatal(_app + _err + "no pipe or input parameter found, example: tlsinfo github.com")
	}
}

//
// LITTLE GENERIC HELPER SECTION
//

// out ...
func out(msg string) {
	os.Stdout.Write([]byte(msg))
}

// isPipe ...
func isPipe() bool {
	out, _ := os.Stdin.Stat()
	return out.Mode()&os.ModeCharDevice == 0
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

// isEnv
func isEnv(in string) bool {
	if _, ok := syscall.Getenv(in); ok {
		return true
	}
	return false
}
