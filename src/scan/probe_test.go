/**
 * @author Blue Thunder Somogyi
 *
 * Copyright (c) 2016 Blue Thunder Somogyi
 */
package scan

import (
	"fmt"
	"net"
	"os"
	"testing"
	"time"
)

// Simple example of alternative constructor
func ExampleNewProbe() {
	//logging.InitDefault()

	test, err := newProbe("127.0.0.1", "192.168.1.1", 2001, 1999)
	if err == nil {
		fmt.Println("Source: ", test.Source.String())
		fmt.Println("Target: ", test.Target.String())
	}
	// Output:
	// Source:  127.0.0.1:2001
	// Target:  192.168.1.1:1999
}

// Simple example of alternative constructor
func ExampleGetResult() {
	//logging.InitDefault()

	test, err := newProbe("127.0.0.1", "192.168.1.1", 2001, 1999)
	result := ResultType{Raw: fmt.Errorf("i/o timeout"), State: FILTERED}
	test.Result = result
	
	if err == nil {
		fmt.Println("Probe:", test.GetResult())
	}
	// Output:
	// Probe: 192.168.1.1:1999 	result: FILTERED

}

// Test1Send attempt connection to an unused local port, ensuring connection failure
func Test1Send(t *testing.T) {
	t.Parallel()

	unused := GetPort()
	//	t.Log("Test1Send: Select Target Port: ", unused)
	test, err := newProbe("", "", 2001, unused)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error: ", err.Error())
		t.Fatalf("Fatal error: %s", err.Error())
	}

	test.Timeout = 3 * time.Second
	err = test.Send()

	if err != nil {
		t.Log("Test1Send: test failed to run")
		t.Fail()
	}
	if test.Result.Raw == nil {
		t.Log("test.Result == nil, expected != nil")
		t.Fail()
	}

}

// Test2Send obtains a valid IP address for well known service (www.google.com:80) and
// attempts connection against that target, expecting successful TCP connection
func Test2Send(t *testing.T) {
	t.Parallel()
	//TestListener.TestListener()
	addrs, err := net.LookupHost("www.google.com")
	if err != nil {
		t.Log("Test2Send: LookupHost err.Error(): ", err.Error())
		t.Fail()
	}

	test, err := newProbe("", addrs[0], 2003, 80)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error: ", err.Error())
		t.Fatalf("Fatal error: %s", err.Error())
	}

	test.Timeout = 3 * time.Second
	err = test.Send()
	if err != nil {
		t.Log("Test2Send: test failed to run")
		t.Fail()
	}
	if test.Result.Raw != nil {
		t.Log("test.Result != nil, expected == nil")
		t.Fail()
	}

}

// Test3Send attempt connection to an unused local port, ensuring connection failure
// while specifying a timeout value
func Test3Send(t *testing.T) {
	t.Parallel()
	unused := GetPort()
	//	t.Log("Test1Send: Select Target Port: ", unused)
	test, err := newProbe("", "", 2001, unused)
	test.Timeout = 3 * time.Second

	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error: ", err.Error())
		t.Fatalf("Fatal error: %s", err.Error())
	}

	err = test.Send()

	if err != nil {
		t.Log("Test3Send: test failed to run")
		t.Fail()
	}
	if test.Result.Raw == nil {
		t.Log("test.Result == nil, expected != nil")
		t.Fail()
	}

}

// Test4Send obtains a valid IP address for well known service (www.google.com:80) and
// attempts connection against that target, expecting successful TCP connection
func Test4Send(t *testing.T) {
	t.Parallel()
	//TestListener.TestListener()
	addrs, err := net.LookupHost("www.google.com")
	if err != nil {
		t.Log("Test4Send: LookupHost err.Error(): ", err.Error())
		t.Fail()
	}

	test, err := newProbe("", addrs[0], 2003, 80)
	test.Timeout = 3 * time.Second

	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error: ", err.Error())
		t.Fatalf("Fatal error: %s", err.Error())
	}

	err = test.Send()
	if err != nil {
		t.Log("Test4Send: test failed to run")
		t.Fail()
	}
	if test.Result.Raw != nil {
		t.Log("test.Result != nil, expected == nil")
		t.Fail()
	}

}

// Test5Send attempts to connect to a non-routable IP address with a timeout,
// expecting a timeout to occur.
func Test5Send(t *testing.T) {
	t.Parallel()

	test, err := newProbe("", "127.10.10.10", 2001, 2001)
	test.Timeout = 3 * time.Second

	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error: ", err.Error())
		t.Fatalf("Fatal error: %s", err.Error())
	}

	err = test.Send()

	if err != nil {
		t.Log("Test5Send: test failed to run")
		t.Fail()
	}
	if test.Result.Raw == nil {
		t.Log("test.Result == nil, expected != nil")
		t.Fail()
	}

}

// Test6Send attempts to connect to an IPv6 address with a timeout,
// expecting a timeout to occur.
func Test6Send(t *testing.T) {
	t.Parallel()

	test, err := newProbe("", "2607:f8b0:4006:807::2004", 2001, 2001)
	test.Timeout = 3 * time.Second

	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error: ", err.Error())
		t.Fatalf("Fatal error: %s", err.Error())
	}

	test.Timeout = 3 * time.Second
	err = test.Send()
	if err != nil {
		t.Log("Test5Send: test failed to run")
		t.Fail()
	}
	if test.Result.Raw == nil {
		t.Log("test.Result == nil, expected != nil")
		t.Fail()
	}

}

/////
// Testing Helper functions
// functions used for test validation
/////

// checkError is generic routine to abort on unexpected error condition
func checkError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error: %s", err.Error())
		os.Exit(1)
	}
}

func createListener(service string) {

	tcpAddrDst, err := net.ResolveTCPAddr("tcp", service)
	checkError(err)

	listener, err := net.ListenTCP("tcp", tcpAddrDst)
	checkError(err)

	listener.SetDeadline(time.Now().Add(time.Second))

	defer listener.Close()

	conn, err := listener.Accept()
	conn.Close()

}
