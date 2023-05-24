package scanner

import (
	"net"
)

type Scan struct {
	Network     []*net.IPNet
	SingleIP    []net.IP
	Port        Port
	Retry       int
	MultiThread bool
}

type Port struct {
	Single       []int
	Range        [][]int
	Exclude      []int
	ExcludeRange [][]int
}

func (s *Scan) HandleScan(t int) {
	switch t {
	case 0:
		s.HandleSynScan()
		break
	}
}

func (s *Scan) HandleSynScan() {

}
