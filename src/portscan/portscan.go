package main

import (
	//"fmt"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"scan"
	//"time"
)

var (
	Trace   *log.Logger
	Info    *log.Logger
	Warning *log.Logger
	Error   *log.Logger
)

func init() {
	debug := os.Getenv("LOGLVL")

	switch debug {
	case "trace":
		LogInit(os.Stdout, os.Stdout, os.Stdout, os.Stderr)
	case "info":
		LogInit(ioutil.Discard, os.Stdout, os.Stdout, os.Stderr)
	case "warning":
		LogInit(ioutil.Discard, ioutil.Discard, os.Stdout, os.Stderr)
	case "error":
		LogInit(ioutil.Discard, ioutil.Discard, ioutil.Discard, os.Stderr)
	default:
		// default to warning or greater
		LogInit(ioutil.Discard, ioutil.Discard, os.Stdout, os.Stderr)
	}
}
func LogInit(
	traceHandle io.Writer,
	infoHandle io.Writer,
	warningHandle io.Writer,
	errorHandle io.Writer) {

	Trace = log.New(traceHandle,
		"TRACE: ",
		log.Ldate|log.Ltime|log.Lshortfile)

	Info = log.New(infoHandle,
		"INFO: ",
		log.Ldate|log.Ltime|log.Lshortfile)

	Warning = log.New(warningHandle,
		"WARNING: ",
		log.Ldate|log.Ltime|log.Lshortfile)

	Error = log.New(errorHandle,
		"ERROR: ",
		log.Ldate|log.Ltime|log.Lshortfile)

}

// ProcessParameters declares all command line flags, and calls all subroutines
// for processing specific command line parameters
func ProcessParameters(params *scan.Params, cmdname string) (err error) {

	portFlag := flag.String("port", "1-65535", "single port, or range of ports to scan")
	timeoutFlag := flag.Int("timeout", 5, "probe timeout value(s), '0' for system default")
	throttleFlag := flag.Int("throttle", 1000000, "concurrent probes")
	//outputFlag := flag.String("output", "stdout", "filename to use instead of console")
	//connectFlag := flag.Bool("showall", false, "display all scan results, not only answering ports")
	//sourceFlag := flag.String("addr", "", "source interface address: defaults to local routed interface")
	//sourcePortFlag := flag.Int("srcport", 0, "source port for probes: defaults to random")

	flag.Parse()

	Trace.Println("params.ParsePortsOpt(portFlag)")
	err = params.ParsePortsOpt(portFlag)
	if err != nil {
		fmt.Println(err.Error())
		PrintUsage(cmdname)
		return
	}
	err = params.ParseTimeoutOpt(timeoutFlag)
	if err != nil {
		fmt.Println(err.Error())
		PrintUsage(cmdname)
		return
	}
	err = params.ParseThrottleOpt(throttleFlag)
	if err != nil {
		fmt.Println(err.Error())
		PrintUsage(cmdname)
		return
	}
	err = params.ParseTimeoutOpt(timeoutFlag)
	if err != nil {
		fmt.Println(err.Error())
		PrintUsage(cmdname)
		return
	}
	err = params.ParsePortsOpt(portFlag)
	if err != nil {
		fmt.Println(err.Error())
		PrintUsage(cmdname)
		return
	}
	params.SetTargetArgs(flag.Args())
	return
}

// PrintUsage outputs the command line syntax and all the parameter defaults
func PrintUsage(cmdname string) {
	fmt.Printf("%s: [flags] target1 target2...\n target = [ip addr | CIDR net] eg 127.0.0.1 10.0.0.0/24\n", filepath.Base(cmdname))
	flag.PrintDefaults()
}

/*
func throwError(err error) {
	Error.Printf("Fatal Error: %s\n", err)
	os.Exit(1)
}
*/

/*
// outputScan
func outputScan(scan *scan.Scan) (err error) {
	var oerr error
	var result *string
	var count int

	for {

		select {
		case result = <-scan.Output:
			Trace.Println("outputScan: result = <-scan.Output")
			fmt.Printf(*result)

		case oerr = <-scan.Errors:
			Trace.Println("outputScan: oerr = <-scan.Errors:")
			fmt.Println(oerr.Error())
		default:
			Trace.Println("outputScan: default:")
			select {
			case <-scan.Done:
				Trace.Println("outputScan: <-scan.Done:")
				return
			case <-time.After(time.Nanosecond * 1000000000):
				count++
				Trace.Println("outputScan: count=", count)
				if count > 10 {
					err = fmt.Errorf("outputScan error: count > 60")
					return err
				}
				continue
			}

		}
	}
}
*/

func main() {

	params := &scan.Params{}

	err := ProcessParameters(params, os.Args[0])
	if err != nil {
		os.Exit(1)
	}

	scan, err := scan.NewScan(params)
	if err != nil {
		Error.Printf("%s\n", err)
	}

	// Defer the close of the done channel to shutdown stray goroutines on program close
	defer close(scan.Done)

	// Initiate processing of target list
	scan.ProcessTargets()

	// Begin target processing
	scan.PerformScan()

	// Wait for output to complete
	<-scan.OutputDoneChan
//	err = outputScan(scan)

}
