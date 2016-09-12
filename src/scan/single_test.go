package scan

import (
	"fmt"
	//"net"
	"testing"
	"time"
	//	"os"
	//	"strconv"
)


// Test Single.Scan success unthrottled
func Test1SingleScan(t *testing.T) {
	t.SkipNow()
	t.Parallel()
	
	test, err := newSingle("", "127.0.0.1", 3900, 4000)
	test.Timeout = 5 * time.Second

	if err == nil {

		test.Scan(0)
		validateSingleScan(test, t)
	} else {
		t.Logf("Test1SingleScan: %s", err.Error())
		t.Fail()
	}
}

// Test Single.Scan success throttled
func Test2SingleScan(t *testing.T) {
	t.SkipNow()
	t.Parallel()

	test, err := newSingle("", "127.0.0.1", 3900, 4000)
	test.Timeout = 1 * time.Second

	if err == nil {
		test.Scan(50)
		validateSingleScan(test, t)
	} else {
		t.Logf("Test1SingleScan: %s", err.Error())
		t.Fail()
	}
}

// Test Single.Scan IPv6
func Test3SingleScan(t *testing.T) {
	t.SkipNow()
	t.Parallel()

	test, err := newSingle("", "2607:f8b0:4006:807::2004:81", 80, 80)
	test.Timeout = 1 * time.Second

	if err == nil {
		test.Scan(50)
		validateSingleScan(test, t)
	} else {
		t.Logf("Test1SingleScan: %s", err.Error())
		t.Fail()
	}
}



// Simple example of alternative Single constructor
func ExampleNewSingle() {
	test, err := newSingle("127.0.0.1", "192.168.1.1", 1, 65535)
	if err == nil {
		fmt.Println("Source:", test.Source.String())
		fmt.Println("Target:", test.Target.String())
		fmt.Println("FirstPort:", test.FirstPort)
		fmt.Println("LastPort:", test.LastPort)
		fmt.Println("len(Results):", len(test.Results))
	}
	// Output:
	// Source: 127.0.0.1
	// Target: 192.168.1.1
	// FirstPort: 1
	// LastPort: 65535
	// len(Results): 65535
}
