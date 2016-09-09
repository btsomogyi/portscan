// Package scan implements the scan logic to trigger multiple probe events
package scan

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math"
	"net"
	"os"
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

type Single struct {
	Source    *net.IPAddr
	Target    *net.IPAddr
	FirstPort int
	LastPort  int
	Timeout   time.Duration
	Results   []*Probe
	Channel   chan *Probe
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

// NewSingle provides a validated constructor for a new Single object.  Returns Single object
// and any errors encountered during address validation.
func NewSingle(sourceAddr, targetAddr string, firstPort, lastPort int) (temp *Single, err error) {
	err = CheckPorts(firstPort, lastPort)
	if err != nil {
		return &Single{}, err
	}
	temp = &Single{FirstPort: firstPort, LastPort: lastPort}

	temp.Source, err = net.ResolveIPAddr("ip", sourceAddr)
	if err != nil {
		//		fmt.Fprintf(os.Stderr, "NewSingle error: %s", err.Error())
	} else {
		temp.Target, err = net.ResolveIPAddr("ip", targetAddr)
		if err != nil {
			//			fmt.Fprintf(os.Stderr, "NewSingle error: %s", err.Error())
		}
	}
	temp.Results = make([]*Probe, lastPort-firstPort+1)
	return temp, err
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

// Single.Scan implements the scan defined by a Single object field values
func (s *Single) Scan(throttle int) {
	// used to track the number of goroutines to catch on channel
	expected := len(s.Results)

	// define throttle channel
	var inflight chan int

	// create throttle channel
	// if abs(throttle) > expected, create buffer equal to
	// 'expected' size to avoid unnecessary channel buffer capacity
	switch {
	case throttle > 0:
		if throttle > expected {
			inflight = make(chan int, expected)
		} else {
			inflight = make(chan int, throttle)
		}
	case throttle < 0:
		if -throttle > expected {
			inflight = make(chan int, expected)
		} else {
			inflight = make(chan int, -throttle)
		}
	default:
		inflight = make(chan int, expected)
	}

	// create receiver channel (*Probe)
	s.Channel = make(chan *Probe)

	// create goroutine to launch scans (which are goroutines)
	go func() {
		// Iterate through Probes defined within Single object, spawning goroutines
		for port := s.FirstPort; port <= s.LastPort; port++ {
			inflight <- port
			next, err := NewProbe(s.Source.String(), s.Target.String(), 0, port)
			if err == nil {
//				//next.Timeout = s.Timeout
				//	fmt.Fprintf(os.Stderr, "Scan launch: %s %s %i %i\n", s.Source.String(), s.Target.String(), 0, port)

				// create goroutine to execute Probe.Send and send to Single.Channel upon completion
				go func(next *Probe) {
					//fmt.Fprintf(os.Stderr, "Multi.Scan func2() [next.Target]: %s\n", next.Target.String())
					err := next.Send(s.Timeout)
					if err != nil {
						fmt.Fprintf(os.Stderr, "Single.Scan: Fail: p.Target.String() %s\n", next.Target.String())
						// log err
					}
					//	fmt.Fprintf(os.Stderr, "Single.Scan: Run: p.Target.String() %s\n", p.Target.String())

					// Always put the Probe on the return channel, even if returns error
					// to ensure proper count and cleanup of channel
					s.Channel <- next
				}(next)
				// increment the number of launched Probes
				//			expected++
			}
		}
	}()

	//	fmt.Fprintf(os.Stderr, "Single.Scan: [expected] %d\n", expected)

	// receiver loop - when receive result, append to Single.Results, then remove
	// token from throttle channel.  Exit when receive count matches expected
	for received := 0; received < expected; received++ {
		latest := <-s.Channel
		s.Results[latest.Target.Port-s.FirstPort] = latest
		<-inflight
	}

}
