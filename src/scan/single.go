package scan 

import (
	//"flag"
	"fmt"
	"net"
	"os"
	//"path/filepath"
	"time"
)

type Single struct {
	Source    *net.IPAddr
	Target    *net.IPAddr
	FirstPort int
	LastPort  int
	Timeout   time.Duration
	Results   []*Probe
	Channel   chan *Probe
}

/////
// Constructors
/////

// NewSingle provides a validated constructor for a new Single object.  Returns Single object
// and any errors encountered during address validation.
func newSingle(sourceAddr, targetAddr string, firstPort, lastPort int) (temp *Single, err error) {
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

/////
// Methods
/////

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
			next, err := newProbe(s.Source.String(), s.Target.String(), 0, port)
			if err == nil {
				next.Timeout = s.Timeout
				//	fmt.Fprintf(os.Stderr, "Scan launch: %s %s %i %i\n", s.Source.String(), s.Target.String(), 0, port)

				// create goroutine to execute Probe.Send and send to Single.Channel upon completion
				go func(next *Probe) {
					//fmt.Fprintf(os.Stderr, "Multi.Scan func2() [next.Target]: %s\n", next.Target.String())
					err := next.Send()
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