package main

import (
	//"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"scan"
)

var (
	Trace   *log.Logger
	Info    *log.Logger
	Warning *log.Logger
	Error   *log.Logger
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

func throwError(err error) {
	Error.Printf("Fatal Error: %s\n", err)
	os.Exit(1)
}

// input method parses the user input and adds targets to the multi.Targets channel.
// For each target to be added to the multi.Targets channel, the number of probes
// for that target is calculated and pushed on the probeCount channel.
// Listens for closure of the done channel to signal premature app shutdown
// closes the inputFinished channel when all user input has been processed

/*
func input(params *scan.Params, multi *scan.Multi, inputFinished chan<- struct{}, probeCount chan<- int, done <-chan bool) {
	select {
		case <-done:
			defer close(inputFinish)
			defer close(probeCount)
		default:
			// add to probeCount, add to target channel
	}
	 
}


// processor consumes the targets placed on the multi.Targets channel.
// 
func processor(multi *scan.Multi, results chan *probe, probeCount <-chan int, inputFinished <-chan struct {}, done <-chan bool) {
	var target *net.IPAddr
	var expected int
	var received int
	for {
		select {
			case count <-probeCount:
				expected += count
			case target <- multi.Targets:
			// create Single in goroutine, pass results channel
			case <-done:
				// done asserted, defer channel close and return
			default:
				select {
					case <-results:
						// remove token from throttle, send probe to output, increment received++
						<-throttle
						received++
						
					default:
					select {
						case <-inputFinished:
							// check that received == expected, if so, break loop
						default:
						// cycle loop for more results
					}
					
				}
		}
	}
}

*/

/*
func driver(probeCount <-chan[int], inputFinished <-chan[struct {}], done chan[struct {}]<-) {
	
	
}
*/

func main() {

	params := &scan.Params{}

	err := ProcessParameters(params, os.Args[0])
	if err != nil {
		os.Exit(1)
	}
	
	scan, err := scan.NewScan(params)
	if err != nil {
		Error.Printf("%s\n", err)
	}

	// Defer the close of the done channel to shutdown stray goroutines on program close
	defer close(scan.Done)
	
	// Initiate processing of target list
	scan.ProcessTargets() 
	
	// Begin target processing
	scan.PerformScan()
	
	err = outputScan(scan)
	
/*
	userSpec, err := scan.NewMulti("127.0.0.1", params.firstPort, params.lastPort)
	if err != nil {
		throwError(err)
	}

	err = params.InitializeMulti(userSpec)
	if err != nil {
		throwError(err)
	}

	//	err = userSpec.Scan()
	userSpec.Scan()
	if err != nil {
		throwError(err)
	}

	oerrs := outputMulti(userSpec)
	if oerrs != nil {
		for anerr := range oerrs {
			Error.Printf("Output Error: %s\n", anerr)
		}
	}
*/

}
