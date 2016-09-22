/**
 * @author Blue Thunder Somogyi
 *
 * Copyright (c) 2016 Blue Thunder Somogyi
 */

// Package scan implements the portscan functionality in a reusable package.
// Overview:
//	*Params object can be used to initialize a Scan object.
//	*The Scan object is the driver of portscan process, using two goroutine
//	based methods, Scan.ProcessTargets() and Scan.PerformScan()
//	* ProcessTargets() ingests a list of IP Address values and puts them on
//	a channel for PerformScan() to consume.
//	* PerformScan() consumes the target channel input provided by ProcessTargets
//	while maintaining a throttle channel to rate limit execution of Probe.Send()s.
//	* CompleteScan() waits for completion signals and returns with an error on
//	any abnormal signal assertions.  Otherwise returns when all output is ready
//	to process.
//		The Scan object has two function pointers, OutputF and ErrorF, that
//	can be used to customize the output and error handling behavior respectively.
//

package portscan

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

/////
// Logging
/////

// Initialize
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

var (
	Trace   *log.Logger
	Info    *log.Logger
	Warning *log.Logger
	Error   *log.Logger
)

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
// Constants and Structs
/////

// Maximum TCP port value
const MAXPORT = 65535

// SLEEPTIME is number of milliseconds which the ProcessScan function will
// sleep when no work is available in channels, but scan not yet complete
const SLEEPTIME = 100

// Params holds the functional parameters needed for a scan object to function
type Params struct {
	firstPort  int
	lastPort   int
	throttle   int
	timeout    time.Duration
	srcPort    int
	source     *net.IPAddr
	targetArgs *[]string
}

// OutputFunc is the method used to process Probe results
type OutputFunc func(*Probe) error

// ErrorFunc is the method used to process Error stream
type ErrorFunc func(error)

// Scan object is primary means of utilizing scan package, providing creating
// code with all needed methods to initialize and drive a portscan.  OutputF
// can be overridden for advanced output processing (eg sorting)
type Scan struct {
	Params
	Targets        chan *net.IPAddr
	Done           chan struct{}
	Errors         chan error
	OutputDoneChan chan struct{}
	OutputF        OutputFunc
	ErrorF         ErrorFunc
	resultsChan    chan *Probe
	inputDoneChan  chan struct{}
	throttleChan   chan int
	expectedChan   chan int
}

/////
// Constructors
/////

// NewScan initializes a new Scan object using Params values.
func NewScan(params *Params) (scan *Scan, err error) {
	err = params.adjustRlimit()
	scan = &Scan{}
	scan.Params = *params
	if scan.source == nil {
		var temp error
		scan.source, temp = net.ResolveIPAddr("ip", "127.0.0.1")
		if temp != nil {
			scan.source, _ = net.ResolveIPAddr("ip", "::1")
		}
	}
	scan.OutputF = defaultOutput
	scan.ErrorF = defaultError
	scan.Targets = make(chan *net.IPAddr, 0)
	scan.Done = make(chan struct{})
	scan.Errors = make(chan error, 0)
	scan.resultsChan = make(chan *Probe)
	scan.inputDoneChan = make(chan struct{})
	scan.OutputDoneChan = make(chan struct{})
	scan.expectedChan = make(chan int, 0)
	scan.throttleChan = make(chan int, params.throttle)
	Trace.Printf("NewScan() [throttle: %d]\n", scan.throttle)
	return
}

/////
// Scan Methods
/////

// NewProbe creates a new probe object based on scan params.  Returns probe object
// and any errors encountered during address validation.
func (scan *Scan) NewProbe(targetAddr string, targetPort int) (probe *Probe, err error) {
	err = CheckPorts(scan.firstPort, targetPort)
	if err != nil {
		return &Probe{}, err
	}

	probe, err = newProbe(scan.source.String(), targetAddr, scan.srcPort, targetPort)

	if err == nil {
		probe.Timeout = scan.timeout
	}

	return probe, err
}

// ProcessTargets takes a list of strings expected to be IP address or CIDR
// format (IPv4|IPv6).  The function returns immediately, pushing all entries
// on the scan.Targets and scan.Errors channels.  Listens for closure of
// scan.Done channel to abort further processing of input.
func (scan *Scan) ProcessTargets() {

	Trace.Println("Entering Scan.ProcessTargets, len(targets)=", len(*scan.targetArgs))
	// Ensure values to work with
	if len(*scan.targetArgs) <= 0 {
		scan.Errors <- fmt.Errorf("Scan.ProcessTargets error: Zero targets input")
		close(scan.Done)
	}

	// First check done channel for preemptive closure, else proceed.
	// For each target string passed, check whether it parses as a single IP
	// value, and if it does not, check if it parses as a CIDR subnet.  If
	// single IP address, push to scan.Targets channel, if CIDR subnet, enumerate
	// all IP addresses in CIDR block and add to params.targetIPs.  Throw
	// error to error channel if string value fails to parse as either.
	//
	go func() {
		var in int
		for _, target := range *scan.targetArgs {
			targetIP := net.ParseIP(target)
			select {
			case <-scan.Done:
				// cleanup and abort
				defer close(scan.inputDoneChan)
				return
			default:
				{
					// if single ipaddr push to targets channel, and continue loop
					if targetIP != nil {
						Trace.Println("Scan.ProcessTargets targetIP:", targetIP.String())
						ipaddr, _ := net.ResolveIPAddr("ip", targetIP.String())
						scan.Targets <- ipaddr
						in++
						continue
					}

					// Attempt subnet parsing
					targetNetNum, targetNetwork, neterr := net.ParseCIDR(target)

					if neterr == nil {
						Trace.Println("Scan.ProcessTargets targetNetwork:", targetNetwork)
						Trace.Println("Scan.ProcessTargets targetNetmask:", targetNetwork)
						for targetIP := targetNetNum.Mask(targetNetwork.Mask); 
								targetNetwork.Contains(targetIP); incrementIP(targetIP) {
							select {
							case <-scan.Done:
							// cleanup and abort
							default:
								ipaddr, _ := net.ResolveIPAddr("ip", targetIP.String())
								scan.Targets <- ipaddr
								in++
							}

						}
						continue
					}

					Trace.Println("Scan.ProcessTargets error():", neterr)
					if neterr != nil {
						// invalid entry, push error on channel and continue processing input
						scan.Errors <- fmt.Errorf("Scan.ProcessTargets error: invalid target value [target: %s]", target)
						continue
					}

				}
			}

		}
		if in > 0 {
			Trace.Println("Scan.ProcessTargets close(scan.inputDoneChan)")
			close(scan.inputDoneChan)
		} else {
			Trace.Println("Scan.ProcessTargets no valid targets - close(scan.DoneChan)")
			scan.Errors <- fmt.Errorf("No valid targets provided - aborting")
			close(scan.Done)
		}
	}() // end go func()

}

// PerformScans begins processing targets from the scan.Targets channel, pushing
// results and errors onto scan.Results channel and scan.Errors (respectively).
// Listens for closure of the scan.inputFinished channel to signal that all input
// has been pushed and to await completion of all pending probes.  Determines that
// all results have been received based on the calculated number of probes from
// all generated single objects.
// Utilizes the scan.throttle to rate limit the number of active probes concurrently
// by removing tokens from scan.throttle as results are received from scan.Results.
// Targets are processed from scan.Targets channel in goroutine, but utilize
// throttle channel to rate limit probe creation.
// Listens for closure of scan.Done to abort further processing.
func (scan *Scan) PerformScan() {
	Trace.Println("Scan.PerformScan()")
	go func() {
		var total int
		var received int
		for {
			// Highest priority channel is 'Done', signaling abort of scan
			select {
			case <-scan.Done:
				Trace.Println("Scan.PerformScan case <-scan.Done:")
				// cleanup and abort
				defer close(scan.OutputDoneChan)
				return
			default:
				// Second tier priority is:
				// * Increment expected value to ensure expected is current
				// * Service target channel to spawn more probes
				// * Service result channel to process results and free throttle slots
				// ** only if no work in these channels drop to default and check
				// ** for completion of all probes
				select {
				case count := <-scan.expectedChan:
					total += count
					Trace.Printf("Scan.PerformScan case count := <-scan.expectedChan: [total: %d] [count: %d]\n", total, count)

				case nextTarget := <-scan.Targets:
					Trace.Printf("Scan.PerformScan case nextTarget := <-scan.Targets: [nextTarget: %s]\n", nextTarget.IP.String())
					// Spawn goroutine to convert target addresses into probe objects,
					// rate limited by the throttle channel buffer size
					go func() {
						for port := scan.firstPort; port <= scan.lastPort; port++ {
							probe, err := scan.NewProbe(nextTarget.IP.String(), port)
							if err != nil {
								scan.Errors <- err
							}
							// wait for throttle availability before starting probe.send()
							Trace.Printf("Scan.PerformScan goroutine: [nextTarget: %s]\n", nextTarget.IP.String())
							scan.throttleChan <- 1
							probe.SendAsync(scan)
						}
						// Submit quantity of probes results expected from last
						// target entry to expectedChan
						Trace.Printf("Scan.PerformScan scan.expectedChan <-: [nextTarget: %s] [expected: %d]\n", nextTarget.IP.String(), scan.lastPort-scan.firstPort+1)
						scan.expectedChan <- scan.lastPort - scan.firstPort + 1
					}()

				case result := <-scan.resultsChan:
					Trace.Printf("Scan.PerformScan case result := <-scan.resultsChan: [result: %s]\n", result.GetResult())
					// Remove token from throttleChan since resultChan signals completion
					// of a probe.  Process the results and push to output channel.
					received++
					<-scan.throttleChan
					oerr := scan.OutputF(result)
					if oerr != nil {
						scan.Errors <- oerr
					}

				case cherr := <-scan.Errors:
					// Receive and error from the error channel and process it
					// with registered error handler
					scan.ErrorF(cherr)

				default:
					// Third tier priority is check if inputDone channel is closed,
					// and if it is determine if all results expected have been
					// received
					select {
					case <-scan.inputDoneChan:
						Trace.Printf("Scan.PerformScan case <-scan.inputDoneChan: [total: %d] [received: %d]\n", total, received)
						if total > 0 && total-received == 0 {
							// All input has been placed on targets channel, converted
							// to probes, and results received - scan complete
							close(scan.OutputDoneChan)
							return
						} else {
							// Otherwise, there are outstanding probes not yet complete.
							// Sleep and continue processing loop
							time.Sleep(time.Nanosecond * 1000000 * SLEEPTIME)
							continue
						}
					case <-time.After(time.Nanosecond * 1000000 * SLEEPTIME):
						Trace.Println("Scan.PerformScan case <-time.After")
						// inputDoneChan not yet closed, more targets yet to be put on
						// targets channel.  Sleep
						continue
					}

				}

			}
		}
	}()
}

// CompleteScan waits for the completion of the scan, and returns and error if scan completed abnormally (scan.Done closed).
// Returns without error when all scan output is ready to be processed, and ensures all goroutines are terminated (by
// closing scan.Done).
func (scan *Scan) CompleteScan() (err error) {
	select {
	case <-scan.Done:
		// Abnormal termination
		err = fmt.Errorf("Abnormal termination of scan")
		return
	case <-scan.OutputDoneChan:
		// Normal termination - signal Done in case of stray goroutine
		close(scan.Done)
		return
	}
}

/////
// Param Methods
/////

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

	// target Rlimit is below current Rlimit, return without any adjustments
	case throttleHeadroom < float64(rLimit.Cur):
		return

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

// ParsePortsOpt validates flag values sent to specify the range of ports to be probed
func (params *Params) ParsePortsOpt(ports *string) (err error) {
	split := strings.Split(*ports, "-")
	var firsterr, lasterr error
	if len(split) > 2 {
		err = fmt.Errorf("Port parameter error: invalid specification [ports: %s]", *ports)
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
		err = fmt.Errorf("Port parameter error: empty ports string")
		return
	case firsterr != nil:
		err = firsterr
		return
	case lasterr != nil:
		err = lasterr
		return
	case params.firstPort > MAXPORT || params.firstPort < 1:
		err = fmt.Errorf("Port parameter error: starting port outside range 1-%d [port: %d]",
			MAXPORT, params.firstPort)
		return
	case params.lastPort > MAXPORT || params.lastPort < 1:
		err = fmt.Errorf("Port parameter error: last port outside range 1-%d [port: %d]",
			MAXPORT, params.lastPort)
		return
	case params.lastPort < params.firstPort:
		err = fmt.Errorf("Port parameter error: starting port greater than last port [start port: %d, last port: %d]",
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
		err = fmt.Errorf("Timeout parameter error: timeout must be >= 1 [timeout: %d]",
			*timeout)
	}
	return
}

// ParseThrottleOpt validates the timeout value passed in flag
func (params *Params) ParseThrottleOpt(throttle *int) (err error) {
	if *throttle >= 1 {
		params.throttle = *throttle
	} else if *throttle <= -1 {
		err = fmt.Errorf("Throttle parameter error: throttle must be >= 0 [throttle: %d]",
			*throttle)
	}
	return
}

// SetTargetArgs sets the package private Params targetArgs field
func (params *Params) SetTargetArgs(targetArgs []string) (err error) {
	if len(targetArgs) == 0 {
		err = fmt.Errorf("Target parameter error: at least one target parameter required")
	}
	params.targetArgs = &targetArgs

	return
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
// Utility functions
/////

func defaultOutput(probe *Probe) error {
	fmt.Printf(probe.GetResult())
	return nil
}

func defaultError(err error) {
	fmt.Println(err.Error())
}

func CheckPorts(firstPort, lastPort int) (err error) {
	if firstPort > 0 && lastPort <= MAXPORT && firstPort <= lastPort {
		return
	} else {
		err = fmt.Errorf("checkPort error: invalid port range (firstPort: %d, lastPort: %d)", firstPort, lastPort)
		return
	}
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

// dumpParams prints all parameter struct contents
func dumpParams(params *Params) {
	Trace.Println("dumpParams firstPort:", params.firstPort)
	Trace.Println("dumpParams lastPort:", params.lastPort)
	Trace.Println("dumpParams throttle:", params.throttle)
	Trace.Println("dumpParams timeout:", params.timeout)
	Trace.Println("dumpParams source:", params.source)
	Trace.Println("dumpParams srcPort:", params.srcPort)
	for idx, target := range *params.targetArgs {
		Trace.Printf("dumpParams targetIP: %s idx: %d", target, idx)
	}
}
