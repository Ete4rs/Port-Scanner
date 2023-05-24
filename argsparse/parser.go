package argsparse

import (
	"flag"
	"fmt"
	"net"
	"strconv"
	"strings"
)

type Scan struct {
	Network  []*net.IPNet
	SingleIP []net.IP
	Port     Port
}

type Port struct {
	Single       []int
	Range        [][]int
	Exclude      []int
	ExcludeRange [][]int
}

func NewArgumentParser() *Scan {
	synScan := flag.Bool("syn", false, "SYN Scan technique")
	tcpConnectScan := flag.Bool("tcp", true, "Full tcp connection")
	finScan := flag.Bool("fin", false, "FIN Scan technique")
	xmasScan := flag.Bool("xmas", false, "Xmas Scan technique")
	nullScan := flag.Bool("null", false, "Null Scan technique")
	ackScan := flag.Bool("ack", false, "ACK Scan technique")
	windowScan := flag.Bool("window", false, "Window Scan technique")
	udpScan := flag.Bool("udp", false, "UDP Scan technique")
	target := flag.String("target", "", "target(for example : 1.1.1.1/24,1.1.1.1")
	port := flag.String("port", "", "target port")
	exclude := flag.String("exclude", "", "exclude port")
	help := flag.Bool("help", false, "Show help")
	flag.Parse()
	if *help {
		flag.PrintDefaults()
		return nil
	}
	if false {
		fmt.Println(target, synScan, tcpConnectScan, finScan, xmasScan, nullScan, ackScan, windowScan, udpScan)
	}
	scan := Scan{}
	*port = strings.TrimSpace(*port)
	if *port == "" {
		fmt.Println("no port, i am scanning all ports")
		arr := []int{0, 65535}
		scan.Port.Range = append(scan.Port.Range, arr)
	} else {
		fmt.Println(*port)
		parsePort(*port, &scan, true)
	}
	if *exclude != "" {
		parsePort(*exclude, &scan, false)
	}
	if *target == "" {
		fmt.Println("no target for scanning")
		return nil
	} else {
		parseTargetIP(*target, &scan)
	}
	return &scan
}

func parseTargetIP(target string, scan *Scan) {
	targets := strings.Split(target, ",")
	for i := 0; i < len(targets); i++ {
		if strings.Contains(targets[i], "/") {
			_, ipNet, err := net.ParseCIDR(targets[i])
			if err != nil {
				fmt.Println("bad input for ip/cidr")
				return
			}
			scan.Network = append(scan.Network, ipNet)
		} else {
			scan.SingleIP = append(scan.SingleIP, net.ParseIP(targets[i]))
		}
	}
}

func parsePort(port string, scan *Scan, f bool) {
	p := strings.Split(port, ",")
	for i := 0; i < len(p); i++ {
		if strings.Contains(p[i], "-") {
			parseRangePort(p[i], scan, f)
		} else {
			var v int
			convertStringToInt(p[i], &v)
			if f {
				scan.Port.Single = append(scan.Port.Single, v)
			} else {
				scan.Port.Exclude = append(scan.Port.Exclude, v)
			}
		}
	}
}

func parseRangePort(p string, scan *Scan, f bool) {
	ranges := strings.Split(p, "-")
	if len(ranges) != 2 {
		fmt.Println("bad input for port")
		return
	}
	var (
		portFirst int
		portLast  int
	)
	convertStringToInt(ranges[0], &portFirst)
	convertStringToInt(ranges[1], &portLast)
	r := []int{portFirst, portLast}
	if f {
		scan.Port.Range = append(scan.Port.Range, r)
	} else {
		scan.Port.ExcludeRange = append(scan.Port.ExcludeRange, r)
	}
}

func convertStringToInt(value string, v *int) {
	va, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		fmt.Println("bad input for port : " + err.Error())
		return
	}
	*v = va
}
