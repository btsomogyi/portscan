/**
 * @author Blue Thunder Somogyi
 *
 * Copyright (c) 2016 Blue Thunder Somogyi
 */
package main

import (
	"github.com/btsomogyi/portscan"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

/////
// Logging
/////

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

/////
// Output
/////

// OutputKey implements a comparable struct to act as key for OutputMap
type OutputKey struct {
	Addr string
	Port int
}

func (ok OutputKey) String() string {
	return fmt.Sprintf("%s:%d", ok.Addr, ok.Port)
}

type OutputKeys []OutputKey

func (ok OutputKeys) Len() int { return len(ok) }

func (ok OutputKeys) Swap(i, j int) { ok[i], ok[j] = ok[j], ok[i] }

func (ok OutputKeys) Less(i, j int) bool { 
	switch {
		case ok[i].Addr < ok[j].Addr:
		return true
		case ok[i].Addr == ok[j].Addr && ok[i].Port < ok[j].Port:
		return true
		default:
		return false
	} 
}

// OutputMap stores result values pending final sort and display
var OutputMap map[OutputKey]string

// MapResults adds result data to map for sorting prior to output.  This is a
// custom output function provided to the Scan object to allow the result
// data to be post-processed after the scan is complete.
func MapResults(probe *portscan.Probe) (err error) {
	NewKey := OutputKey{Addr: probe.Target.IP.String(), Port: probe.Target.Port}
	OutputMap[NewKey] = probe.GetResult()
	return
}

// PortscanOutput sorts the map of output results generated by the custom
// output function provided to the Scan object, then outputs them to the
// console
func PortscanOutput() (err error) {
	var keys OutputKeys
	keys = make(OutputKeys, 0)
	for k := range OutputMap {
		keys = append(keys, k)
	}
	sort.Sort(keys)

	for _, k := range keys {
		fmt.Printf(OutputMap[k])
	}

	return
}

/////
// Input
/////

// ProcessParameters declares all command line flags, and calls all subroutines
// for processing specific command line parameters
func ProcessParameters(params *portscan.Params, cmdname string) (sort bool, err error) {

	portFlag := flag.String("port", "1-65535", "single port, or range of ports to scan")
	timeoutFlag := flag.Int("timeout", 5, "probe timeout value(s), '0' for system default")
	throttleFlag := flag.Int("throttle", 1000000, "concurrent probes")
	sortFlag := flag.String("sort", "y", "(y/n) sort results before outputing (large scans will require sufficient memory)")
	//connectFlag := flag.Bool("showall", false, "display all scan results, not only answering ports")
	//sourceFlag := flag.String("addr", "", "source interface address: defaults to local routed interface")
	//sourcePortFlag := flag.Int("srcport", 0, "source port for probes: defaults to random")

	flag.Parse()
	
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
	
	err = params.SetTargetArgs(flag.Args())
	if err != nil {
		fmt.Println(err.Error())
		PrintUsage(cmdname)
		return
	}
			
	// invalid sort flag is non-fatal
	var serr error
	sort, serr = ParseSortOpt(sortFlag)
	if serr != nil {
		fmt.Println(serr.Error())
	}
	
	return
}

// ParseSortOpt validates the sort value passed in flag
func ParseSortOpt(sort *string) (doSort bool, err error) {
	switch {
	case strings.Contains(*sort, "yes"):
		doSort = true
	case *sort == "y" || *sort == "Y":
		doSort = true
	case strings.Contains(*sort, "no"):
		doSort = false
	case *sort == "n" || *sort == "N":
		doSort = false
	default:
		err = fmt.Errorf("Unknown sort input [%s]: defaulting to sort=yes", *sort)
		doSort = true
	}

	return doSort, err
}

// PrintUsage outputs the command line syntax and all the parameter defaults
func PrintUsage(cmdname string) {
	fmt.Printf("%s: [flags] target1 target2...\n target = [ip addr | CIDR net] eg 127.0.0.1 10.0.0.0/24\n", filepath.Base(cmdname))
	flag.PrintDefaults()
}

/////
// Main()
/////

// netscan main ()
func main() {

	// Initialize blank Params struct and pass to parameter parser
	params := &portscan.Params{}

	sort, err := ProcessParameters(params, os.Args[0])
	if err != nil {
		os.Exit(1)
	}
	
	// Initialize empty OutputMap
	OutputMap = make(map[OutputKey]string)

	scan, err := portscan.NewScan(params)
	if err != nil {
		Error.Printf("%s\n", err)
	}

	// Assign custom output function if sort requested
	if sort == true {
		scan.OutputF = MapResults
	}

	// Defer the close of the done channel to shutdown stray goroutines on program close
	defer close(scan.Done)

	// Initiate processing of target list
	scan.ProcessTargets()

	// Begin target processing
	scan.PerformScan()

	// Wait for output to complete
	<-scan.OutputDoneChan

	// Sort and output results
	if sort == true {
		PortscanOutput()
	}

}