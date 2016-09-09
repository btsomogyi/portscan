package main

import (
	"fmt"
	"net"
	//	"os"
	//	"strconv"
	"testing"
	"time"
)

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

// Test1ParseTargetArg - good input (single addrs)
func Test1ParseTargetArg(t *testing.T) {
	argSlice := []string{"127.0.0.1", "2001:db8::68"}
	params := &Params{}
	var err error
	if err = params.ParseTargetArg(argSlice); err != nil {
		t.Logf("Test1ParseTargetArg error: %s\n", err)
		t.Fail()
	}
	if err = validateParamArgs(params, len(argSlice)); err != nil {
		t.Logf("Test1ParseTargetArg error: %s\n", err)
		t.Fail()
	}
}


// Test2ParseTargetArg - good input (CIDR addrs)
func Test2ParseTargetArg(t *testing.T) {
	t.SkipNow()
	argSlice := []string{"192.168.0.0/30"}
	params := &Params{}
	var err error
	if err = params.ParseTargetArg(argSlice); err != nil {
		t.Logf("Test2ParseTargetArg error: %s\n", err)
		t.Fail()
	}
	if err = validateParamArgs(params, 256); err != nil {
		t.Logf("Test2ParseTargetArg error: %s\n", err)
		t.Fail()
	}
}

// Test3ParseTargetArg - good input (subnets)
func Test3ParseTargetArg(t *testing.T) {
	argSlice := []string{"192.168.0.10/24", "2001:db8::68/127"}
	params := &Params{}
	var err error
	if err = params.ParseTargetArg(argSlice); err != nil {
		t.Logf("Test3ParseTargetArg error: %s\n", err)
		t.Fail()
	}
	if err = validateParamArgs(params, 258); err != nil {
		t.Logf("Test3ParseTargetArg error: %s\n", err)
		t.Fail()
	}
}

// Test4ParseTargetArg - good input (mixed ip and subnet)
func Test4ParseTargetArg(t *testing.T) {
	argSlice := []string{"192.168.0.10", "2001:db8::68/127"}
	params := &Params{}
	var err error
	if err = params.ParseTargetArg(argSlice); err != nil {
		t.Logf("Test4ParseTargetArg error: %s\n", err)
		t.Fail()
	}
	if err = validateParamArgs(params, 3); err != nil {
		t.Logf("Test4ParseTargetArg error: %s\n", err)
		t.Fail()
	}
}


// Test5ParseTargetArg - bad input (bad addr)
func Test5ParseTargetArg(t *testing.T) {
	argSlice := []string{"192.168.0.296", "2001:db8:"}
	params := &Params{}
	var err error
	if err = params.ParseTargetArg(argSlice); err == nil {
		t.Logf(" error: %s\n", err)
		t.Logf("Test5ParseTargetArg bad input (bad addr) uncaught: [argSlice: %s]\n",
			argSlice)
		t.Fail()
	}
	if err = validateParamArgs(params, len(argSlice)); err == nil {
		t.Logf("Test5ParseTargetArg bad input (bad addr) uncaught: [argSlice: %s]\n",
			argSlice)
		t.Fail()
	}
}

// Test1incrementIP - good input (single addrs)
func Test1incrementIP(t *testing.T) {
	//argSlice := []string{"192.168.0.1"}
	ip := net.ParseIP("192.168.0.1")
	//params := &Params{}
	//var err error
	incrementIP(ip)
	if ! ip.Equal(net.ParseIP("192.168.0.2")) {
		t.Logf("Test1incrementIP [ip: %s] expected '192.168.0.2'\n", ip.String())
		t.Fail()
	}
}

/* Testing Helper functions
// functions used for test validation
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

// validateParamArgs checks for valid Params.timeout values
func validateParamArgs(params *Params, numArgs int) (err error) {
//	Info.Printf("validateParamArgs:[len(params.targetIPs): %d] [numArgs: %d]\n", len(params.targetIPs), numArgs)

	tested := make([]net.IP, 0)

	for _, target := range params.targetIPs {
//		Info.Printf("validateParamArgs:[index: : %d] [target: %d]\n", idx, target)
		tempIP := net.ParseIP(target.String())

		if tempIP != nil {
//			Info.Printf("validateParamArgs:[tempIP: %s]\n", tempIP.String())
			tested = append(tested, tempIP)
		}
	}

	if len(tested) != numArgs {
		err = fmt.Errorf("validateParamTimeout error: len(params.targetIPs) != numArgs [len(params.targetIPs): %d]\n",
			len(tested))
/*		for idx, testedGood := range tested {
			Info.Printf("validateParamArgs:[index: : %d] [testedGood: %d]\n", idx, testedGood)
		}
		*/
	}
	return
}
