package main

import ("scan" 
	"fmt")

// outputMulti loops through
func outputMulti (multi *scan.Multi) (err []error) {
	err = make([]error, 0)
	for _, target := range multi.Results {
		for _,probe := range target.Results {
			//Info.Printf("outputMulti targetIP: %s port: %d result: %s\n", probe.Target.IP, probe.Target.Port, probe.Result)
			_,perr := fmt.Printf("%s:%d result: %s \n", probe.Target.IP, probe.Target.Port, probe.Result.State.String())
			if perr != nil {
				err = append(err, perr)
			}
		}
	}
	return
}