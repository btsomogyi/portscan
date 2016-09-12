// Package scan implements the scan logic to trigger multiple probe events
package scan

import (
	//"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math"
	"net"
	"os"
	//"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
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

const MAXPORT = 65535

// SLEEPTIME is number of milliseconds which the ProcessScan function will
// sleep when no work is available in channels, but scan not yet complete
const SLEEPTIME = 1000

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

// Scan object is primary means of utilizing scan package, providing creating
// code with all needed methods to initialize and drive a portscan
type Scan struct {
	Params
	Targets       chan *net.IPAddr
	Output        chan *string
	Done          chan struct{}
	Errors        chan error
	resultsChan   chan *Probe
	inputDoneChan chan struct{}
	throttleChan  chan int
	expectedChan  chan int
}

type Multi struct {
	Source    *net.IPAddr
	Targets   []*net.IPAddr
	FirstPort int
	LastPort  int
	Timeout   time.Duration
	Throttle  int
	Results   []*Single
	Channel   chan *Single
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
	scan.Targets = make(chan *net.IPAddr)
	scan.Output = make(chan *string)
	scan.Done = make(chan struct{})
	scan.Errors = make(chan error)
	scan.resultsChan = make(chan *Probe)
	scan.inputDoneChan = make(chan struct{})
	scan.expectedChan = make(chan int)
	scan.throttleChan = make(chan int, params.throttle)
	Trace.Printf("NewScan() [throttle: %d]\n", scan.throttle)
	return
}

// NewMulti provides a validated constructor for a new Multi object.  Returns Multi object
// and any errors encountered during address validation.  Use AddMultiIP to increment Targets list
func NewMulti(sourceAddr string, firstPort, lastPort int) (temp *Multi, err error) {
	err = CheckPorts(firstPort, lastPort)
	if err != nil {
		return &Multi{}, err
	}
	temp = &Multi{FirstPort: firstPort, LastPort: lastPort}

	temp.Source, err = net.ResolveIPAddr("ip", sourceAddr)
	if err != nil {
		//		fmt.Fprintf(os.Stderr, "NewSingle error: %s", err.Error())
	}
	return temp, err
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
		for _, target := range *scan.targetArgs {
			targetIP := net.ParseIP(target)
			select {
			case <-scan.Done:
			// cleanup and abort
			default:
				{
					// if single ipaddr push to targets channel, and continue loop
					if targetIP != nil {
						Trace.Println("Scan.ProcessTargets targetIP:", targetIP.String())
						ipaddr, _ := net.ResolveIPAddr("ip", targetIP.String())
						//params.targetIPs = append(params.targetIPs, ipaddr)
						scan.Targets <- ipaddr
						continue
					}

					// Attempt subnet parsing
					targetNetNum, targetNetwork, neterr := net.ParseCIDR(target)

					if neterr == nil {
						Trace.Println("Scan.ProcessTargets targetNetwork:", targetNetwork)
						Trace.Println("Scan.ProcessTargets targetNetmask:", targetNetwork)
						for targetIP := targetNetNum.Mask(targetNetwork.Mask); targetNetwork.Contains(targetIP); incrementIP(targetIP) {
							select {
							case <-scan.Done:
							// cleanup and abort
							default:
								ipaddr, _ := net.ResolveIPAddr("ip", targetIP.String())
								scan.Targets <- ipaddr
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
		Trace.Println("Scan.ProcessTargets close(scan.inputDoneChan)")
		close(scan.inputDoneChan)
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
			default:
				Trace.Println("Scan.PerformScan default:")
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
						Trace.Printf("Scan.PerformScan scan.expectedChan <-: [nextTarget: %s] [expected: %d]\n", nextTarget.IP.String(), scan.lastPort - scan.firstPort + 1)
						scan.expectedChan <- scan.lastPort - scan.firstPort + 1
					}()
					
				case result := <-scan.resultsChan:
					Trace.Printf("Scan.PerformScan case result := <-scan.resultsChan: [result: %s]\n", result.GetResult())
					// Remove token from throttleChan since resultChan signals completion
					// of a probe.  Process the results and push to output channel.
					<-scan.throttleChan
					probeOutput := result.GetResult()
					scan.Output <- &probeOutput
					
				default:
					Trace.Println("Scan.PerformScan default:")
					// Third tier priority is check if inputDone channel is closed,
					// and if it is determine if all results expected have been
					// received
					select {
					case <-scan.inputDoneChan:
						Trace.Printf("Scan.PerformScan case <-scan.inputDoneChan: [total: %d] [received: %d]\n", total, received)
						if total > 0 && total-received == 0 {
							// All input has been placed on targets channel, converted
							// to probes, and results received - scan complete
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

/////
// Multi Methods
/////

//  AddMultiIP adds an IP address to Multi object via string (utilty function)
func (m *Multi) AddMultiIP(targetAddr string) (err error) {
	temp, err := net.ResolveIPAddr("ip", targetAddr)
	if err != nil {
		return err
	}
	m.Targets = append(m.Targets, temp)
	return
}

//  AddMultiIPSlice adds an IP addresses to Multi object via IPAddr slice
func (m *Multi) AddMultiIPSlice(targetAddr []*net.IPAddr) (err error) {
	Trace.Println("Entered AddMultiIPSlice")
	if len(targetAddr) == 0 {
		err = fmt.Errorf("ParseTimeoutOpt error: empty targetAddr slice")
		return
	}

	// Concatenate additional targets to Multi target list
	m.Targets = append(m.Targets, targetAddr...)
	return
}

func CheckPorts(firstPort, lastPort int) (err error) {
	if firstPort > 0 && lastPort <= MAXPORT && firstPort <= lastPort {
		return
	} else {
		err = fmt.Errorf("checkPort error: invalid port range (firstPort: %d, lastPort: %d)", firstPort, lastPort)
		return
	}
}

// Multi.Scan implements the scan across multiple targets.  The throttle value
// is use to determine the maximum number of concurrent probe.Send() goroutines
// that should be allowed simultaneously.  This is implemented using a two-
//  stage channel - the 'inflight' channel sets the buffer size to the maximum
// number of Single objects that should be in-flight simultaneously.  Each
// Single object attempts to push its index (arbitrary token) onto the inflight
// channel before calling its Single.Scan() function, and blocks if the inflight
// channel is currently full.  Once a Single.Scan() is complete it sends its
// results on the receiver channel, and upon receipt of the result, a token is
// removed from the throttle channel.
//
// Throttling strategy:
// When throttle exceeds (nodes * probes), there is no bottleneck, and both
// breadth and depth can be set to respective max.  When throttle is less than
// nodes * probes, maximization of throughput is required (depth * breadth ~=
// throttle).
// Settings are selected based on the four quadrants below
//
//                  sqrt(T) > N        sqrt(T) < N
//               __________________________________
//              |               |                 |   T = Throttle
// sqrt(T) > P  |   B=N  D=P    |  B=T/S  D=S     |   P = Probes (per target)
//              |   (T > N*P)   |                 |   N = Nodes (to be scanned)
//              |---------------------------------|   B = Breadth (concurrent
//              |               |                 |       nodes)
// sqrt(T) < P  |  B=N  D=T/N   |  B = sqrt(T)    |   D = Depth (concurrent
//              |               |  D = sqrt(T)    |       probes per target)
//               __________________________________
//
//
func (m *Multi) Scan() {
	Trace.Println("Entered Multi.Scan()")

	throttle := m.Throttle
	// calculate throttle = global maximum divided by the number of Sends per Single
	nodes := len(m.Targets)
	probes := m.LastPort - m.FirstPort + 1
	Trace.Println("Multi.Scan nodes::", nodes)
	Trace.Println("Multi.Scan probes:", probes)

	// take sqrt of throttle value, rounded up to nearest integer (avoids corner case)
	t2root := int(math.Ceil(math.Sqrt(float64(throttle))))
	Trace.Println("Multi.Scan throttle:", throttle)
	Trace.Println("Multi.Scan t2root:", t2root)

	var depth int
	var breadth int
	switch {
	case throttle >= nodes*probes:
		Trace.Println("throttle >= nodes*probes")
		depth = probes
		breadth = nodes
	case t2root <= nodes && t2root <= probes:
		Trace.Println("t2root <= nodes && t2root <= probes")
		depth = t2root
		breadth = t2root
	case t2root <= nodes:
		Trace.Println("t2root <= nodes")
		breadth = throttle / probes
		depth = probes
	case t2root <= probes:
		Trace.Println("t2root <= probes")
		breadth = nodes
		depth = throttle / nodes
	}

	// slight optimization that if high throttle makes breadth larger than
	// number of nodes, reduce to number of nodes, in order to prevent overallocation
	// of buffer space in 'inflight' channel
	if breadth > nodes {
		breadth = nodes
	} else if breadth < 1 { // correct for integer division truncation corner cases
		breadth = 1
	}
	if depth < 1 {
		depth = 1
	}

	Trace.Println("Multi.Scan breadth:", breadth)
	Trace.Println("Multi.Scan depth:", depth)

	// create throttle channel (int)
	inflight := make(chan int, breadth)
	// create receiver channel (*Single)
	m.Channel = make(chan *Single)

	// create goroutine to launch scans (which are goroutines)
	go func() {
		for index, target := range m.Targets {
			//			fmt.Fprintf(os.Stderr, "Multi.Scan func1() [index,target]: %d %s\n", index, target.String())
			inflight <- index
			next := &Single{Source: m.Source, Target: target, FirstPort: m.FirstPort, LastPort: m.LastPort, Timeout: m.Timeout}
			next.Results = make([]*Probe, next.LastPort-next.FirstPort+1)
			// create goroutine to execute Single.Scan and send to Multi.Channel upon completion
			go func(next *Single) {
				//				fmt.Fprintf(os.Stderr, "Multi.Scan func2() [next.Target]: %s\n", next.Target.String())
				next.Scan(depth)
				m.Channel <- next
			}(next)
		}
	}()

	// receiver loop - when receive result, append to Multi.Results, then remove
	// token from throttle channel.  Exit when receive count matches expected
	for received := 0; received < len(m.Targets); received++ {
		latest := <-m.Channel
		m.Results = append(m.Results, latest)
		<-inflight
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

// InitializeMulti transfers all options from Params stuct to input Multi object
/*
func (params *Params) InitializeMulti(multi *Multi) (err error) {
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
*/

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

// SetTargetArgs sets the package private Params targetArgs field
func (params *Params) SetTargetArgs(targetArgs []string) (err error) {
	if targetArgs != nil {
		err = fmt.Errorf("SetTargetArgs error: Nil value for targetArgs passed")
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
	//	Trace.Println("dumpParams showall:", params.showall)
	Trace.Println("dumpParams srcPort:", params.srcPort)
	Trace.Println("dumpParams showall:", params.firstPort)
	for idx, target := range *params.targetArgs {
		Trace.Printf("dumpParams targetIP: %s idx: %d", target, idx)
	}
}
