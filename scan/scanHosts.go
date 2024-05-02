// Package scan provides types and functions to perform TCP port
// scans on a list of hosts
package scan

import (
	"fmt"
	"net"
	"time"
)

// PortState represents the state of a single TCP port
type PortState struct {
	Port int
	Open state
}

type state bool

func (s state) String() string {
	if s {
		return "open"
	}

	return "closed"
}

// scanPort performs a port scan on a single TCP port
func scanPort(host string, port int) PortState {
	p := PortState{
		Port: port,
	}

	address := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	scanConn, err := net.DialTimeout("tcp", address, 1*time.Second)
	if err != nil {
		return p
	}
	scanConn.Close()

	p.Open = true
	return p
}

// Results represent the scan results for a single host
type Results struct {
	Host      string
	NotFound  bool
	PortState []PortState
}

// Run performs a port scan on the hosts list
func Run(hl *HostList, ports []int) []Results {
	res := make([]Results, 0, len(hl.Hosts))

	for _, h := range hl.Hosts {
		r := Results{
			Host: h,
		}

		if _, err := net.LookupHost(h); err != nil {
			r.NotFound = true
			res = append(res, r)
			continue
		}

		for _, p := range ports {
			r.PortState = append(r.PortState, scanPort(h, p))
		}

		res = append(res, r)
	}

	return res
}
