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

func main() {

	params := &Params{}

	err := params.ProcessParameters(os.Args[0])
	if err != nil {
		os.Exit(1)
	}
	
	err = params.adjustRlimit()
	if err != nil {
		Error.Printf("%s\n", err)
	}

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

}
