/**
 * @author Blue Thunder Somogyi
 *
 * Copyright (c) 2016 Blue Thunder Somogyi
 */
package portscan

import (
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"
)

// Probe struct contains the parameters and results of a single port probe
type Probe struct {
	Source  net.TCPAddr
	Target  net.TCPAddr
	Timeout time.Duration
	Result  ResultType
	//	ServiceName string
}

// ResultType holds the raw connection error (if any) and the interpreted result
// and implements the String() method
type ResultType struct {
	Raw   error
	State ResultState
}

func (r *ResultType) String() string {
	return r.State.String() + r.Raw.Error()
}

// ResultState is constant for the interpreted status of a probe attempt and
// implements the String() method
type ResultState uint8

const (
	OPEN ResultState = iota
	FILTERED
	CLOSED
	OTHER
	INVALID
)

func (r ResultState) String() string {
	s := ""
	switch r {
	case OPEN:
		s = "OPEN"
	case FILTERED:
		s = "FILTERED"
	case CLOSED:
		s = "CLOSED"
	case OTHER:
		s = "OTHER"
	case INVALID:
		s = "OTHER"
	}
	return s
}

/////
// Constructors
/////

// NewProbe is an alternative constructor for Probe struct that takes strings
// and converts them to the appropriate TCPAddr types, then returns the resulting
// Probe struct
func newProbe(sourceAddr, targetAddr string, sourcePort, targetPort int) (*Probe, error) {
	Trace.Printf("sourceAddr: %s sourcePort: %d targetAddr: %s targetPort: %d\n", sourceAddr, sourcePort, targetAddr, targetPort)
	// Determine if IPv4 of IPv6 in order to format service string appropriately (enclose IPv6 addr in "[]")

	src, err := net.ResolveIPAddr("ip", sourceAddr)
	if err != nil {
		Error.Printf("probe.NewProbe error: %s", err.Error())
		return &Probe{}, err
	}
	srcAddr := net.TCPAddr{src.IP, sourcePort, src.Zone}

	tgt, iperr := net.ResolveIPAddr("ip", targetAddr)
	if iperr != nil {
		Error.Printf("probe.NewProbe error: %s", err.Error())
		return &Probe{}, err
	}
	tgtAddr := net.TCPAddr{tgt.IP, targetPort, tgt.Zone}

	return &Probe{Source: srcAddr, Target: tgtAddr}, nil
}

/////
// Methods
/////

// Send initiates a probe via a full TCP handshake negotiation with the
// target service using standard 'net' library methods.  The Probe object is
// updated with the results of the connection attempt.  Only Target values are
// required in the Probe object for type one probes, and will use the Timeout
// value from the Probe object if non-zero
func (p *Probe) Send() (fail error) {
	var conn net.Conn
	var err error
	var sleeprange time.Duration

	// Set the amount of time for goroutine to sleep if max file count exceeded
	// If timeout 0 (sys default) or < 4s, sleep 1-2 seconds
	// If timeout longer, sleep for rand(timeout) / 2 seconds
	// Randomized factor is provided during each sleep call
	if int(p.Timeout.Seconds()) <= 4 {
		sleeprange = time.Duration(2) * time.Second
	} else {
		sleeprange = time.Duration(p.Timeout.Seconds()/2) * time.Second
	}

	Trace.Printf("Probe.Send() sleep range: %f s\n", sleeprange.Seconds())

	// Confirm target exists
	if &p.Target != nil {

		// Loop to ensure that if file limit error is hit, sleep to allow other
		// connections to finish and retry
		for {
			if p.Timeout != 0 {
				conn, err = net.DialTimeout("tcp", p.Target.String(), p.Timeout)
				if err != nil {
				}

			} else { // no Timeout set in probe object, use net.Dial
				conn, err = net.Dial("tcp", p.Target.String())
				if err != nil {
				}
			}

			// if connection good or error not regarding open file limit,
			// break out of loop for further processing
			if err == nil || !strings.Contains(err.Error(), "open files") {
				p.Result.Raw = err
				break
			} else {
				// Sleep randomized duration in from 1-sleeprange seconds
				sleeptime := time.Duration(float64(sleeprange.Nanoseconds()) * rand.Float64())
				time.Sleep(sleeptime)
			}
		}
	} else { // No Target in probe object
		Error.Println("probe.Send Error: probe.Target not set")
		fail = fmt.Errorf("probe.Send Error: probe.Target not set")
	}

	// close connection if successful and mark target service as OPEN
	if conn != nil {
		defer conn.Close()
		p.Result.State = OPEN
	} else if p.Result.Raw != nil {
		switch {
		case strings.Contains(p.Result.Raw.Error(), "timed out") ||
			strings.Contains(p.Result.Raw.Error(), "i/o timeout"):
			p.Result.State = FILTERED
		case strings.Contains(p.Result.Raw.Error(), "refused"):
			p.Result.State = CLOSED
		case strings.Contains(p.Result.Raw.Error(), "permission denied") ||
			strings.Contains(p.Result.Raw.Error(), "route to host"):
			p.Result.State = INVALID
		default:
			Trace.Printf("Probe.Send() switch default err.Error(): %s\n", p.Result.Raw.Error())
			p.Result.State = OTHER
		}

	} else {
		// Signal unknown error
		Error.Println("probe.Send Error: no connection made, no error returned")
		fail = p.Result.Raw
	}

	return
}

// SendAsync initiates a probe.Send() with inputs of done, results, and
// error channels.  If done channel remains open when probe.Scan returns
// any error is pushed on the err channel and the probe is pushed on the results
// channel.

func (p *Probe) SendAsync(s *Scan) {
	Trace.Printf("Probe.SendAsync() Enter... [p.Target IP:%s] [p.Port: %d] [p.Timeout: %d]\n", p.Target.IP.String(), p.Target.Port, p.Timeout)
	go func() {
		err := p.Send()
		select {
		case <-s.Done:
			return
		default:
			{
				if err != nil {
					s.Errors <- err
				}
				s.resultsChan <- p
			}
		}
	}()
}

// GetResult formats the probe result data for output
func (p *Probe) GetResult() (result string) {
	if p.Result.Raw != nil {
		Info.Printf("Probe.GetResult() [Result.Error():%s]\n", p.Result.Raw.Error())
	}
	return fmt.Sprintf("%s:%d \tresult: %s \n", p.Target.IP, p.Target.Port, p.Result.State.String())
}

// GetPort obtains a free unused port and confirms it can be bound
func GetPort() int {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		panic(err)
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		panic(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}
