package main

import (
	"flag"
	"fmt"
	"path/filepath"
	"scan"
	"time"
)

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

// outputMulti loops through
func outputMulti(multi *scan.Multi) (err []error) {
	err = make([]error, 0)
	for _, target := range multi.Results {
		for _, probe := range target.Results {
			//Info.Printf("outputMulti targetIP: %s port: %d result: %s\n", probe.Target.IP, probe.Target.Port, probe.Result)
			_, perr := fmt.Printf("%s:%d result: %s \n", probe.Target.IP, probe.Target.Port, probe.Result.State.String())
			if perr != nil {
				err = append(err, perr)
			}
		}
	}
	return
}

// outputScan
func outputScan(scan *scan.Scan) (err error) {
	var oerr error
	var result *string
	var count int

	for {

		select {
		case result = <-scan.Output:
			Trace.Println("outputScan: result = <-scan.Output")
			fmt.Println(result)

		case oerr = <-scan.Errors:
			Trace.Println("outputScan: oerr = <-scan.Errors:")
			fmt.Println(oerr.Error())
		default:
			Trace.Println("outputScan: default:")
			select {
			case <-scan.Done:
				Trace.Println("outputScan: <-scan.Done:")
				return
			case <-time.After(time.Second):
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
