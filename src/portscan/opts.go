package main

import (
	"flag"
	"fmt"
	"net"
	"path/filepath"
	"scan"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const MAXPORT = 65535

type Params struct {
	firstPort int
	lastPort  int
	throttle  int
	timeout   time.Duration
	showall   bool
	srcPort   int
	source    *net.IPAddr
	targetIPs []*net.IPAddr
}

// ProcessParameters declares all command line flags, and calls all subroutines
// for processing specific command line parameters
func (params *Params) ProcessParameters(cmdname string) (err error) {

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
	err = params.ParseTargetArg(flag.Args())
	if err != nil {
		fmt.Println(err.Error())
		PrintUsage(cmdname)
		return
	}
	dumpParams(params)
	return
}

// PrintUsage outputs the command line syntax and all the parameter defaults
func PrintUsage(cmdname string) {
	fmt.Printf("%s: [flags] target1 target2...\n target = [ip addr | CIDR net] eg 127.0.0.1 10.0.0.0/24\n", filepath.Base(cmdname))
	flag.PrintDefaults()
}

// adjustRlimit modifies the system ulimit for the process context to 125% the throttle
// value (if needed), or adjusts the throttle down to 80% of hard ulimit if unable
func (params *Params) adjustRlimit() (err error) {
	var rLimit syscall.Rlimit
	var rLimitTarget uint64

	err = syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		Error.Println("Error Getting Rlimit ", err)
		err = fmt.Errorf("Unable to get Rlimit: Not able to guarentee throttle performance")
		return
	}
	Info.Printf("Initial Rlimit.Cur: %d\n", rLimit.Cur)
	Info.Printf("Initial Rlimit.Max: %d\n", rLimit.Max)

	// Precalculate target values
	throttleHeadroom := float64(params.throttle) * 1.25

	switch {
	// current rLimit less than desired, but maximum will allow it
	case throttleHeadroom > float64(rLimit.Cur) && throttleHeadroom < float64(rLimit.Max):
		rLimitTarget = uint64(float64(rLimit.Cur) * 1.25)

	// current limit less than desired, and maximum too low to adjust -
	// set rlimit target equal to maximum, throttle will get haircut later
	case throttleHeadroom > float64(rLimit.Cur) && throttleHeadroom > float64(rLimit.Max):
		rLimitTarget = rLimit.Max

	}

	rLimitPrevious := rLimit.Cur
	rLimit.Cur = rLimitTarget

	err = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		Info.Println("Error Setting Rlimit ", err)
		// Set throttle to 80% of existing RLimit
		params.throttle = int(float64(rLimitPrevious) * 0.8)
		err = nil
	}

	Info.Printf("Adjusted Rlimit.Cur: %d\n", rLimit.Cur)
	Info.Printf("Adjusted Rlimit.Max: %d\n", rLimit.Max)
	Info.Printf("Adjusted throttle: %d\n", params.throttle)

	err = syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		Error.Println("Error Getting Rlimit ", err)
		err = nil
	}

	if throttleHeadroom > float64(rLimit.Cur) {
		// Adjust throttle down to 80% of adjusted rLimit
		params.throttle = int(float64(rLimit.Cur) * 0.8)
		Info.Printf("Adjusting throttle to %d due to Rlimit ceiling %d", params.throttle, rLimit.Cur)
	}

	return
}

// InitializeMulti transfers all options from Params stuct to input Multi object

func (params *Params) InitializeMulti(multi *scan.Multi) (err error) {
	Trace.Println("Entered InitializeMulti")
	multi.FirstPort = params.firstPort
	multi.LastPort = params.lastPort
	multi.Timeout = params.timeout
	multi.Throttle = params.throttle
	if len(params.targetIPs) > 0 {
		err = multi.AddMultiIPSlice(params.targetIPs)
	}
	return
}

// ParsePortsOpt validates flag values sent to specify the range of ports to be probed
func (params *Params) ParsePortsOpt(ports *string) (err error) {
	split := strings.Split(*ports, "-")
	var firsterr, lasterr error
	if len(split) > 2 {
		err = fmt.Errorf("ParsePortsOpt error: len(split) != 2 [ports: %s]", *ports)
		return
	}

	// if only a single port value passed, use it for both starting and ending
	params.firstPort, firsterr = strconv.Atoi(split[0])
	if len(split) == 2 {
		params.lastPort, lasterr = strconv.Atoi(split[1])
	} else { // len(split) == 1
		params.lastPort = params.firstPort
		lasterr = nil
	}

	switch {
	case len(*ports) == 0:
		err = fmt.Errorf("ParsePortsOpt error: empty ports string")
		return
	case firsterr != nil:
		err = firsterr
		return
	case lasterr != nil:
		err = lasterr
		return
	case params.firstPort > MAXPORT || params.firstPort < 1:
		err = fmt.Errorf("ParsePortsOpt error: firstPort outside range 1-%d [firstPort: %d]",
			MAXPORT, params.firstPort)
		return
	case params.lastPort > MAXPORT || params.lastPort < 1:
		err = fmt.Errorf("ParsePortsOpt error: lastPort outside range 1-%d [firstPort: %d]",
			MAXPORT, params.lastPort)
		return
	case params.lastPort < params.firstPort:
		err = fmt.Errorf("ParsePortsOpt error: firstPort greater than lastPort [firstPort: %d, lastPort: %d]",
			params.firstPort, params.lastPort)
		return
	}

	return
}

// ParseTimeoutOpt validates the timeout value passed in flag
func (params *Params) ParseTimeoutOpt(timeout *int) (err error) {
	if *timeout >= 1 {
		params.timeout = time.Duration(*timeout) * time.Second
	} else if *timeout <= -1 {
		err = fmt.Errorf("ParseTimeoutOpt error: timeout < 1 [timeout: %d]",
			*timeout)
	}
	return
}

// ParseThrottleOpt validates the timeout value passed in flag
func (params *Params) ParseThrottleOpt(throttle *int) (err error) {
	if *throttle >= 1 {
		params.throttle = *throttle
	} else if *throttle <= -1 {
		err = fmt.Errorf("ParseThrottleOpt error: throttle < 0 [throttle: %d]",
			*throttle)
	}
	return
}

// ParseTargetArg parses the non-flag parameters, all of which are expected
// to be target addresses or subnets
func (params *Params) ParseTargetArg(targets []string) (err error) {
	Trace.Println("Entering ParseTargetArg, len(targets)=", len(targets))
	// Ensure values to work with
	if len(targets) <= 0 {
		err = fmt.Errorf("ParseTargetArg error: len(*targets) <= 0")
		return
	}

	// If targetIPs slice uninitialized, create with zero starting capacity
	if params.targetIPs == nil {
		Trace.Println("ParseTargetArg params.targetIPs == nil, initializing")
		params.targetIPs = make([]*net.IPAddr, 0)
	}
	Trace.Println("ParseTargetArg, len(params.targetIPs)=", len(params.targetIPs))

	// For each target string passed, check whether it parses as a single IP
	// value, and if it does not, check if it parses as a CIDR subnet.  If
	// single IP address, add to params.targetIPs, if CIDR subnet, enumerate
	// all IP addresses in CIDR block and add to params.targetIPs.  Throw
	// error if string value fails to parse as either.
	for _, target := range targets {
		targetIP := net.ParseIP(target)
		if targetIP != nil {
			Trace.Println("ParseTargetArg targetIP:", targetIP.String())
			ipaddr, _ := net.ResolveIPAddr("ip", targetIP.String())
			params.targetIPs = append(params.targetIPs, ipaddr)
			continue
		}

		targetNetNum, targetNetwork, neterr := net.ParseCIDR(target)

		if neterr == nil {
			Trace.Println("ParseTargetArg targetNetwork:", targetNetwork)
			Trace.Println("ParseTargetArg targetNetmask:", targetNetwork)
			for targetIP := targetNetNum.Mask(targetNetwork.Mask); targetNetwork.Contains(targetIP); incrementIP(targetIP) {
				ipaddr, _ := net.ResolveIPAddr("ip", targetIP.String())
				params.targetIPs = append(params.targetIPs, ipaddr)
			}

			continue
		}

		Trace.Println("ParseTargetArg error():", neterr)
		if neterr != nil {
			// invalid entry, set error and stop processing input
			err = neterr
			break
		}
	}
	Trace.Println("ParseTargetArg error():", err)
	return
}

// IncrementIP increments the passed IP address to the next consecutive addr
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// ParseSrcPortOpt validates probe source interface flag
// TBI
func (params *Params) ParseSourceOpt(source *string) (err error) {
	err = fmt.Errorf("ParseSourceOpt error: unimplemented")
	return
}

// ParseSrcPortOpt validates probe source port flag
// TBI
func (params *Params) ParseSrcPortOpt(srcPort *int) (err error) {
	err = fmt.Errorf("ParseSrcPortOpt error: unimplemented")
	return
}

/////
// Utility functions to assist in validation
/////

// dumpParams prints all parameter struct contents

func dumpParams(params *Params) {
	Trace.Println("dumpParams firstPort:", params.firstPort)
	Trace.Println("dumpParams lastPort:", params.lastPort)
	Trace.Println("dumpParams throttle:", params.throttle)
	Trace.Println("dumpParams timeout:", params.timeout)
	Trace.Println("dumpParams source:", params.source)
	Trace.Println("dumpParams showall:", params.showall)
	Trace.Println("dumpParams srcPort:", params.srcPort)
	Trace.Println("dumpParams showall:", params.firstPort)
	for idx, target := range params.targetIPs {
		Trace.Printf("dumpParams targetIP: %s idx: %d", target.String(), idx)
	}
}
