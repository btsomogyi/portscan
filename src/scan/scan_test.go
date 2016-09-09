package scan

import (
	"fmt"
	"testing"
	"time"
)

// Test Single.Scan success unthrottled
func Test1SingleScan(t *testing.T) {
	t.Parallel()
	test, err := NewSingle("", "127.0.0.1", 3900, 4000)
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
	t.Parallel()

	test, err := NewSingle("", "127.0.0.1", 3900, 4000)
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
	t.Parallel()

	test, err := NewSingle("", "2607:f8b0:4006:807::2004:81", 80, 80)
	test.Timeout = 1 * time.Second

	if err == nil {
		test.Scan(50)
		validateSingleScan(test, t)
	} else {
		t.Logf("Test1SingleScan: %s", err.Error())
		t.Fail()
	}
}

// Test Multi.Scan success, single target ( probes > t2root > nodes)
func Test1MultiScan(t *testing.T) {
	//Info.Println("Begin Sequential Multi Test")
	t.Parallel()

	test, err := NewMulti("127.0.0.1", 100, 124)
	if err != nil {
		t.Logf("Test1MultiScan: %s", err.Error())
		t.Fail()
	}
	test.AddMultiIP("192.168.1.1")
	test.Timeout = 5 * time.Second
	test.Throttle = 24

	if err == nil {
		test.Scan()
		validateMultiScan(test, t)
	} else {
		t.Logf("Test1MultiScan: %s", err.Error())
		t.Fail()
	}
}

// Test Multi.Scan success, multiple targets with throttle ( nodes > t2root > probes)
func Test2MultiScan(t *testing.T) {
	t.Parallel()

	test, err := NewMulti("127.0.0.1", 100, 102)
	if err != nil {
		t.Logf("Test1MultiScan: %s", err.Error())
		t.Fail()
	}
	test.AddMultiIP("192.168.1.1")
	test.AddMultiIP("192.168.1.2")
	test.AddMultiIP("192.168.1.3")
	test.AddMultiIP("192.168.1.4")
	test.AddMultiIP("192.168.1.5")
	test.Timeout = 1 * time.Second
	test.Throttle = 10

	if err == nil {
		test.Scan()
		validateMultiScan(test, t)
	} else {
		t.Logf("Test1MultiScan: %s", err.Error())
		t.Fail()
	}
}

// Test Multi.Scan success, three targets, five ports, throttle = 3 ( t2root < nodes & probes)
func Test3MultiScan(t *testing.T) {
	t.Parallel()

	test, err := NewMulti("127.0.0.1", 100, 104)
	if err != nil {
		t.Logf("Test1MultiScan: %s", err.Error())
		t.Fail()
	}
	test.AddMultiIP("192.168.1.1")
	test.AddMultiIP("192.168.1.2")
	test.AddMultiIP("192.168.1.3")
	test.Timeout = 1 * time.Second
	test.Throttle = 3

	if err == nil {
		test.Scan()
		validateMultiScan(test, t)
	} else {
		t.Logf("Test3MultiScan: %s", err.Error())
		t.Fail()
	}
}

// Test Multi.Scan success, two targets, three ports, throttle = 1 (t2root <= nodes & probes)
func Test4MultiScan(t *testing.T) {
	t.Parallel()

	test, err := NewMulti("127.0.0.1", 100, 102)
	if err != nil {
		t.Logf("Test1MultiScan: %s", err.Error())
		t.Fail()
	}
	test.AddMultiIP("192.168.1.1")
	test.AddMultiIP("192.168.1.2")
	test.Timeout = 1 * time.Second
	test.Throttle = 2

	if err == nil {
		test.Scan()
		validateMultiScan(test, t)
	} else {
		t.Logf("Test1MultiScan: %s", err.Error())
		t.Fail()
	}
}

// Test Multi.Scan success, five targets, ten ports, throttle = 100 (throttle >= nodes*probes)
func Test5MultiScan(t *testing.T) {
	t.Parallel()
	test, err := NewMulti("127.0.0.1", 100, 109)
	if err != nil {
		t.Logf("Test1MultiScan: %s", err.Error())
		t.Fail()
	}
	test.AddMultiIP("192.168.1.1")
	test.AddMultiIP("192.168.1.2")
	test.AddMultiIP("192.168.1.3")
	test.AddMultiIP("192.168.1.4")
	test.AddMultiIP("192.168.1.5")
	test.Timeout = 1 * time.Second
	test.Throttle = 500

	if err == nil {
		test.Scan()
		validateMultiScan(test, t)
	} else {
		t.Logf("Test1MultiScan: %s", err.Error())
		t.Fail()
	}
}

// Simple example of alternative Single constructor
func ExampleNewSingle() {
	test, err := NewSingle("127.0.0.1", "192.168.1.1", 1, 65535)
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

// Simple example of alternative Multi constructor
func ExampleNewMulti() {
	test, err := NewMulti("127.0.0.1", 1, 65535)
	if err == nil {
		fmt.Println("Source:", test.Source.String())
		fmt.Println("FirstPort:", test.FirstPort)
		fmt.Println("LastPort:", test.LastPort)
	}
	test.AddMultiIP("192.168.1.1")
	if err == nil {
		for index, target := range test.Targets {
			fmt.Printf("Target[%d]: %s\n", index, target.String())
		}
	}
	// Output:
	// Source: 127.0.0.1
	// FirstPort: 1
	// LastPort: 65535
	// Target[0]: 192.168.1.1
}

// Expected failure due to invalid starting port
func Test1NewSingle(t *testing.T) {
	_, err := NewSingle("127.0.0.1", "192.168.1.1", -1, 65535)
	if err == nil {
		t.Log("invalid starting port: Expected error, NewSingle succeeded")
		t.Fail()
	}
}

// Expected failure due to invalid last port
func Test2NewSingle(t *testing.T) {
	_, err := NewSingle("127.0.0.1", "192.168.1.1", 1, 165535)
	if err == nil {
		t.Log("invalid last port: Expected error, NewSingle succeeded")
		t.Fail()
	}
}

// Expected failure due to last port less than first port
func Test3NewSingle(t *testing.T) {
	_, err := NewSingle("127.0.0.1", "192.168.1.1", 1001, 1000)
	if err == nil {
		t.Log("last port less than first port: Expected error, NewSingle succeeded")
		t.Fail()
	}
}

// Expected failure due to invalid source IP address
func Test4NewSingle(t *testing.T) {
	_, err := NewSingle("127.0.0.", "192.168.1.1", 1, 1000)
	if err == nil {
		t.Log("invalid source IP address: Expected error, NewSingle succeeded")
		t.Fail()
	}
}

// Expected failure due to invalid target IP address
func Test5NewSingle(t *testing.T) {
	_, err := NewSingle("127.0.0.1", "192.168.1.", 1, 1000)
	if err == nil {
		t.Log("invalid target IP address: Expected error, NewSingle succeeded")
		t.Fail()
	}
}


/////
// Helper function to validate test results of Multi tests
/////

// validateSingleScan helper function to validate test results of Single tests
func validateSingleScan(single *Single, t *testing.T) {
	for index, element := range single.Results {
		if element == nil {
			t.Log("Test1SingleScan: incomplete Results, element", index)
			t.Fail()
			break
		}
	}
}

// validateMultiScan helper function to validate test results of Multi tests
func validateMultiScan(multi *Multi, t *testing.T) {
	/*
		fmt.Println("Source:", multi.Source.String())
		fmt.Println("FirstPort:", multi.FirstPort)
		fmt.Println("LastPort:", multi.LastPort)
		fmt.Println("len(Results):", len(multi.Results))
	*/
	for index, element := range multi.Results {
		if element == nil {
			t.Log("MultiScan: incomplete Results, element", index)
			t.Fail()
			break
		}
		//t.Log("Test1Scan: ", index, element.Result)
		for idx, result := range element.Results {
			if result == nil {
				t.Log("MultiScan: incomplete Results, element", idx)
				t.Fail()
				break
			}
			//t.Log("Test1Scan: ", index, element.Result)
		}
	}
}
