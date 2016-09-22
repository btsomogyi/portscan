/*
 * @author Blue Thunder Somogyi
 *
 * Copyright (c) 2016 Blue Thunder Somogyi
 */
package portscan

import (
	"fmt"
	"net"
	"testing"
	"time"
)

/////
// Param test
/////

// Test1ParsePortsOpt - good input
func Test1ParsePortsOpt(t *testing.T) {
	portFlag := "10-100"
	params := &Params{}
	var err error
	if err = params.ParsePortsOpt(&portFlag); err != nil {
		t.Logf("Test1ParsePortsOpt error(): %s\n", err.Error())
		t.Fail()
	}
	if err = validateParamPorts(params); err != nil {
		t.Logf("Test1ParsePortsOpt error(): %s\n", err.Error())
		t.Fail()
	}
}

// Test2ParsePortsOpt - bad input (invalid range)
func Test2ParsePortsOpt(t *testing.T) {
	portFlag := "10-9"
	params := &Params{}
	var err error
	if err = params.ParsePortsOpt(&portFlag); err == nil {
		t.Logf("Test2ParsePortsOpt bad input (invalid range) uncaught: [portFlag: %s]\n",
			portFlag)
		t.Fail()
	}
	if err = validateParamPorts(params); err == nil {
		t.Logf("Test1ParsePortsOpt error(): %s\n", err.Error())
		t.Fail()
	}
}

// Test3ParsePortsOpt - bad input (invalid high port)
func Test3ParsePortsOpt(t *testing.T) {
	portFlag := "10-100000"
	params := &Params{}
	var err error
	if err = params.ParsePortsOpt(&portFlag); err == nil {
		t.Logf("Test3ParsePortsOpt bad input (invalid high port) uncaught: [portFlag: %s]\n",
			portFlag)
		t.Fail()
	}
	if err = validateParamPorts(params); err == nil {
		t.Logf("Test3ParsePortsOpt bad input (invalid high port) uncaught:[firstPort: %d] [lastPort: %d]\n",
			params.firstPort, params.lastPort)
		t.Fail()
	}
}

// Test4ParsePortsOpt - bad input (garbage)
func Test4ParsePortsOpt(t *testing.T) {
	portFlag := "abc123"
	params := &Params{}
	var err error
	if err = params.ParsePortsOpt(&portFlag); err == nil {
		t.Logf("Test4ParsePortsOpt bad input (garbage) uncaught: [portFlag: %s]\n",
			portFlag)
		t.Fail()
	}
	if err = validateParamPorts(params); err == nil {
		t.Logf("Test4ParsePortsOpt bad input (garbage) uncaught:[firstPort: %d] [lastPort: %d]\n",
			params.firstPort, params.lastPort)
		t.Fail()
	}
}

// Test5ParsePortsOpt - bad input (invalid numeric)
func Test5ParsePortsOpt(t *testing.T) {
	portFlag := "10-100x"
	params := &Params{}
	var err error
	if err = params.ParsePortsOpt(&portFlag); err == nil {
		t.Logf("Test5ParsePortsOpt bad input (invalid numeric) uncaught: [portFlag: %s]\n",
			portFlag)
		t.Fail()
	}
	if err = validateParamPorts(params); err == nil {
		t.Logf("Test5ParsePortsOpt bad input (invalid numeric) uncaught:[firstPort: %d] [lastPort: %d]\n",
			params.firstPort, params.lastPort)
		t.Fail()
	}
}

// Test6ParsePortsOpt - bad input (empty string)
func Test6ParsePortsOpt(t *testing.T) {
	portFlag := ""
	params := &Params{}
	var err error
	if err = params.ParsePortsOpt(&portFlag); err == nil {
		t.Logf("Test6ParsePortsOpt bad input (empty string) uncaught: [portFlag: %s]\n",
			portFlag)
		t.Fail()
	}
	if err = validateParamPorts(params); err == nil {
		t.Logf("Test6ParsePortsOpt bad input (empty string) uncaught:[firstPort: %d] [lastPort: %d]\n",
			params.firstPort, params.lastPort)
		t.Fail()
	}
}

func TestParseSourceOpt(t *testing.T) {
	t.SkipNow()
}

func TestParseSrcPortOpt(t *testing.T) {
	t.SkipNow()
}

// Test1ParseTimeoutOpt - good input
func Test1ParseTimeoutOpt(t *testing.T) {
	timeoutFlag := 5
	params := &Params{}
	var err error
	if err = params.ParseTimeoutOpt(&timeoutFlag); err != nil {
		t.Logf("Test1ParseTimeoutOpt error(): %s\n", err.Error())
		t.Fail()
	}
	if err = validateParamTimeout(params); err != nil {
		t.Logf("Test1ParseTimeoutOpt error(): %s\n", err.Error())
		t.Fail()
	}
}

// Test2ParseTimeoutOpt - bad input (negative)
func Test2ParseTimeoutOpt(t *testing.T) {
	timeoutFlag := -1
	params := &Params{}
	var err error
	if err = params.ParseTimeoutOpt(&timeoutFlag); err == nil {
		t.Logf("Test2ParseTimeoutOpt bad input (negative) uncaught: [timeoutFlag: %d]\n",
			timeoutFlag)
		t.Fail()
	}
	if err = validateParamTimeout(params); err == nil {
		t.Logf("Test2ParseTimeoutOpt bad input (negative) uncaught: [timeoutFlag: %d]\n",
			timeoutFlag)
		t.Fail()
	}
}

// Test1ParseThrottleOpt - good input
func Test1ParseThrottleOpt(t *testing.T) {
	throttleFlag := 5
	params := &Params{}
	var err error
	if err = params.ParseThrottleOpt(&throttleFlag); err != nil {
		t.Logf("Test1ParseThrottleOpt error(): %s\n", err.Error())
		t.Fail()
	}
	if err = validateParamThrottle(params); err != nil {
		t.Logf("Test1ParseThrottleOpt error(): %s\n", err.Error())
		t.Fail()
	}
}

// Test2ParseThrottleOpt - bad input (negative)
func Test2ParseThrottleOpt(t *testing.T) {
	throttleFlag := -1
	params := &Params{}
	var err error
	if err = params.ParseThrottleOpt(&throttleFlag); err == nil {
		t.Logf("Test2ParseThrottleOpt bad input (negative) uncaught: [throttleFlag: %d]\n",
			throttleFlag)
		t.Fail()
	}
	if err = validateParamThrottle(params); err != nil {
		t.Logf("Test2ParseThrottleOpt bad input (negative) uncaught: [throttleFlag: %d]\n",
			throttleFlag)
		t.Fail()
	}
}

// Test1Scan.ProcessTargets()  - good input (single addrs)
func Test1ProcessTargets(t *testing.T) {
	argSlice := []string{"127.0.0.1", "2001:db8::68"}
	params := &Params{}
	var err error

	err = params.SetTargetArgs(argSlice)
	if err != nil {
		t.Log(err.Error())
		t.Fail()
	}

	scan, err := NewScan(params)
	scan.ProcessTargets()

	targets, results, errs, err := consumeChannels(t, scan)
	if err != nil {
		t.Log("Test1ProcessTargets: consumeChannels err: %s", err.Error())
		t.Fail()
		return
	}

	// smoke test
	switch {
	case len(targets) != 2:
		t.Logf("Test1ProcessTargets: len(targets) = %d\n", len(targets))
		t.Log("Test1ProcessTargets: len(targets) != 2")
		t.Fail()
		return
	case len(results) != 0:
		t.Logf("Test1ProcessTargets: len(results) = %d\n", len(results))
		t.Log("Test1ProcessTargets: len(results) != 2")
		t.Fail()
		return
	case len(errs) != 0:
		t.Logf("Test1ProcessTargets: len(errs) = %d\n", len(errs))
		t.Log("Test1ProcessTargets: len(errs) != 0")
		t.Fail()
		return
	}

	//check results
	for _, x := range targets {
		if !isValueInList(x.IP.String(), argSlice) {
			t.Logf("Parameter %s not found in returned targets", x)
			t.Fail()
			return
		}
	}
}

// Test2Scan.ProcessTargets()  - bad input (single addrs)
func Test2ProcessTargets(t *testing.T) {
	argSlice := []string{"127.0.0.1", "xyz"}
	params := &Params{}

	var err error
	//	var good, bad int

	err = params.SetTargetArgs(argSlice)
	if err != nil {
		t.Log(err.Error())
		t.Fail()
	}

	scan, err := NewScan(params)
	scan.ProcessTargets()

	targets, results, errs, err := consumeChannels(t, scan)
	if err != nil {
		t.Log("Test1ProcessTargets: consumeChannels err: %s", err.Error())
		t.Fail()
		return
	}

	// smoke test
	switch {
	case len(targets) != 1:
		t.Logf("Test1ProcessTargets: len(targets) = %d\n", len(targets))
		t.Log("Test1ProcessTargets: len(targets) != 2\n")
		t.Fail()
		return
	case len(results) != 0:
		t.Logf("Test1ProcessTargets: len(results) = %d\n", len(results))
		t.Log("Test1ProcessTargets: len(results) != 2")
		t.Fail()
		return
	case len(errs) != 1:
		t.Logf("Test1ProcessTargets: len(errs) = %d\n", len(errs))
		t.Log("Test1ProcessTargets: len(errs) != 0\n")
		t.Fail()
		return
	}

	//check results
	if targets[0].IP.String() != argSlice[0] {
		t.Logf("Test1ProcessTargets: %s != %s\n", targets[0].IP.String(), argSlice[0])
		t.Fail()
		return
	}
}

// Test1incrementIP - good input (single addrs)
func Test1incrementIP(t *testing.T) {
	ip := net.ParseIP("192.168.0.1")

	incrementIP(ip)
	if !ip.Equal(net.ParseIP("192.168.0.2")) {
		t.Logf("Test1incrementIP [ip: %s] expected '192.168.0.2'\n", ip.String())
		t.Fail()
	}
}

/////
// Testing Helper functions
// functions used for test validation
/////

// consumeChannels consumes targets sent by Send.ProcessTargets()
func consumeChannels(t *testing.T, scan *Scan) (targets []*net.IPAddr, results []*Probe, errs []error, err error) {
	targets = make([]*net.IPAddr, 0)
	results = make([]*Probe, 0)
	errs = make([]error, 0)
	count := 0
	for {

		select {
		case nextTarget := <-scan.Targets:
			targets = append(targets, nextTarget)
			t.Log("consumeChannels: len(targets) =", len(targets))

		case result := <-scan.resultsChan:
			results = append(results, result)
			t.Log("consumeChannels: len(results) =", len(results))

		case cherr := <-scan.Errors:
			errs = append(errs, cherr)
			t.Log("consumeChannels: len(errs) =", len(errs))

		default:
			select {
			case <-scan.inputDoneChan:
				t.Log("consumeChannels: case<-scan.inputDoneChan")
				defer close(scan.OutputDoneChan)
				return 
			case <-time.After(time.Second):
				t.Log("consumeChannels: case<-time.After")
				count++
				if count > 10 {
					t.Log("consumeChannels time out")
					defer close(scan.OutputDoneChan)
					return 
				}
				continue
			}

		}
	}

	return 
}

// consumeOutput consumes targets sent by Send.ProcessTargets()
/*
func consumeChannels(t *testing.T, scan *Scan) (targets []*net.IPAddr, results []*Probe, errs []error, err error) {
	results = make([]*Probe, 0)
	targets = make([]*net.IPAddr, 0)
	errs = make([]error, 0)
	count := 0
	for {

		select {
		case nextTarget := <-scan.Targets:
			targets = append(targets, nextTarget)
			t.Log("consumeOutput: len(targets) =", len(targets))

		case result := <-scan.resultsChan:
			results = append(results, result)
			t.Log("consumeOutput: len(targets) =", len(targets))

		case cherr := <-scan.Errors:
			errs = append(errs, cherr)

		default:
			select {
			case <-scan.inputDoneChan:
				defer close(scan.OutputDoneChan)
				return
			case <-time.After(time.Second):
				count++
				if count > 10 {
					return
				}
				continue
			}

		}
	}

	return
}
*/

// validateParamPorts checks for valid Params.firstPort and Params.lastPort values
func validateParamPorts(params *Params) (err error) {
	switch {
	case params.firstPort <= 0:
		err = fmt.Errorf("validateParamPorts error: params.firstPort <= 0 [params.firstPort: %d]\n", params.firstPort)
	case params.firstPort > MAXPORT:
		err = fmt.Errorf("validateParamPorts error: params.firstPort > MAXPORT [params.firstPort: %d]\n", params.firstPort)
	case params.lastPort < params.firstPort:
		err = fmt.Errorf("validateParamPorts error: params.lastPort < params.firstPort [params.firstPort: %d, params.lastPort: %d]\n",
			params.firstPort, params.lastPort)
	case params.lastPort > MAXPORT:
		err = fmt.Errorf("validateParamPorts error: params.lastPort > MAXPORT [params.lastPort: %d]\n", params.lastPort)
	default:
		err = nil
	}
	return
}

// validateParamTimeout checks for valid Params.timeout values
func validateParamTimeout(params *Params) (err error) {
	switch {
	case params.timeout < time.Second:
		err = fmt.Errorf("validateParamTimeout error: params.Timeout < 1s [params.Timeout: %s]\n", params.timeout.String())
	default:
		err = nil
	}
	return
}

// validateParamThrottle checks for valid Params.throttle values
func validateParamThrottle(params *Params) (err error) {
	switch {
	case params.throttle < 0:
		err = fmt.Errorf("validateParamThrottle error: params.throttle < 0 [params.throttle: %s]\n", params.throttle)
	default:
		err = nil
	}
	return
}

// validateParamArgs checks for valid Params.timeout values and number of
func validateParamArgs(params *Params, numArgs int) (err error) {
	tested := make([]net.IP, 0)

	for _, target := range *params.targetArgs {
		tempIP := net.ParseIP(target)

		if tempIP != nil {
			tested = append(tested, tempIP)
		}
	}

	if len(tested) != numArgs {
		err = fmt.Errorf("validateParamTimeout error: len(params.targetIPs) != numArgs [len(params.targetIPs): %d]\n",
			len(tested))
	}
	return
}

// isValueInList find is a string is an entry in a string array
func isValueInList(value string, list []string) bool {
	for _, v := range list {
		if v == value {
			return true
		}
	}
	return false
}
