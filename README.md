# Portscan

Portscan is a Golang implementation of a network port scanner with the following features
- Built using Golang core libraries
- IPv4 and IPv6 network scanning
- Scans are fully concurrent and throttle controlled
- Scans individual IP addresses, CIDR blocks, or a combination

### Installation 
If Golang is already installed, use 'go get' to pull down
```
$ go get github.com/btsomogyi/portscan/cmd/portscan
$ go install github.com/btsomogyi/portscan/cmd/portscan
$ netscan -h
```

### Usage
```
portscan: [flags] target1 target2...
   target = [ip addr | CIDR net] eg 127.0.0.1 10.0.0.0/24
    -port string
         	single port, or range of ports to scan (default "1-65535")
    -sort string
         	(y/n) sort results before outputing (large scans will require sufficient memory) (default "y")
    -throttle int
         	concurrent probes (default 1000000)
    -timeout int
         	probe timeout value(s), '0' for system default (default 5)
```

The Golang net library routines in which portscan is implemented utilize file handles for state, thus the number of outstanding TCP connections is limited by the Ulimit settings of the host system.  Portscan will detect the file Ulimit settings and attempt to adjust to accomodate the throttle setting specified.  If the hard limit does not permit this adjustment, the throttle setting used is automatically adjusted down to prevent incorrect results (due to TCP connection attempt failing to be created due to localhost resource limitations).  Priviledged users are able to adjust the Ulimit hard limit on most systems, so running portscan as a superuser may allow higher throttle values to take effect.  A warning message will be issued to the terminal if the throttle setting is downgraded.

Portscan implements Golang native logging for informational and debug messages.  These can be enabled at the (trace|info|warning|error) levels by setting the environment variable "LOGLVL".

```
$ LOGLVL=trace
$ export LOGLVL
$ portscan 127.0.0.1
```

### Design

Portscan utilizes the Golang native concurrancy features to allow an arbitrarily large network scans to complete using a minimum of system memory (influenced primarily by concurrancy and whether output should be sorted prior to display).

By utilizing the Golang net libraries, portscan is able to handle IP addresses in a version agnostic manner.

The design of the 'scan' package, which contains the core network scanning functionality, is meant to have a clean API, allowing reuse in other applications, and abstracting the Golang concurrancy mechanism.  Additionally, the scan package allows for overriding the output and error reporting functions to allow customization in other programs.

From scan.go
```sh
// Package scan implements the portscan functionality in a reusable package.
// Overview:
//	*Params object can be used to initialize a Scan object.
//	*The Scan object is the driver of portscan process, using two goroutine
//	based methods, Scan.ProcessTargets() and Scan.PerformScan()
//	* ProcessTargets() ingests a list of IP Address values and puts them on
//	a channel for PerformScan() to consume.
//	* PerformScan() consumes the target channel input provided by ProcessTargets
//	while maintaining a throttle channel to rate limit execution of Probe.Send()s.
//		The Scan object has two function pointers, OutputF and ErrorF, that
//	can be used to customize the output and error handling behavior respectively.
```
### License
Apache License, Version 2.0

### TODO
- Implement alternative raw socket based scan (avoiding ulimit issue)
- Implement check for IPv4 & IPv6 interface address check on local system
- Implement source address and port parameters
