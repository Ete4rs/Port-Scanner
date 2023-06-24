package argsparse

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

type Scan struct {
	Network     []*net.IPNet
	SingleIP    []net.IP
	Port        Port
	Retry       int
	MultiThread bool
	Timeout     int
	Output      int
	SrcPort     int
}

type Port struct {
	Single       []int
	Range        [][]int
	Exclude      []int
	ExcludeRange [][]int
}

func NewArgumentParser() (*Scan, int) {
	synScan := flag.Bool("syn", false, "SYN Scan technique")
	tcpConnectScan := flag.Bool("tcp", true, "Full tcp connection")
	finScan := flag.Bool("fin-scan", false, "FIN Scan technique")
	xmasScan := flag.Bool("xmas", false, "Xmas Scan technique")
	nullScan := flag.Bool("null", false, "Null Scan technique")
	ackScan := flag.Bool("ack", false, "ACK Scan technique")
	windowScan := flag.Bool("window", false, "Window Scan technique")
	udpScan := flag.Bool("udp", false, "UDP Scan technique")
	target := flag.String("t", "", "target(for example : 1.1.1.1/24,1.1.1.1")
	port := flag.String("p", "", "target port")
	exclude := flag.String("e", "", "exclude port")
	retry := flag.Int("r", 2, "retry scan the port")
	multiThread := flag.Bool("m", false, "multi thread scanning")
	timeout := flag.Int("time", 10, "timeout packet")
	output := flag.Int("o", 1, "output (1->terminal,  2->txt file)")
	srcPort := flag.Int("src", 7777, "src port")
	help := flag.Bool("h", false, "Show help")
	flag.Parse()
	if *help {
		flag.PrintDefaults()
		os.Exit(0)
	}
	scan := Scan{
		Retry:       *retry,
		MultiThread: *multiThread,
		Timeout:     *timeout,
		Output:      *output,
		SrcPort:     *srcPort,
	}
	*port = strings.TrimSpace(*port)
	if *port == "" {
		fmt.Println("no port, i am scanning all ports")
		arr := []int{0, 65535}
		scan.Port.Range = append(scan.Port.Range, arr)
	} else {
		parsePort(*port, &scan, true)
	}
	if *exclude != "" {
		parsePort(*exclude, &scan, false)
	}
	if *target == "" {
		fmt.Println("no target for scanning")
		os.Exit(0)
	} else {
		parseTargetIP(*target, &scan)
	}
	var t int
	switch true {
	case *synScan:
		t = 0
		break
	case *finScan:
		t = 1
		break
	case *xmasScan:
		t = 2
		break
	case *nullScan:
		t = 3
		break
	case *ackScan:
		t = 4
		break
	case *windowScan:
		t = 5
		break
	case *udpScan:
		t = 6
		break
	case *tcpConnectScan:
		t = 7
		break
	default:
		t = 7
		break
	}
	return &scan, t
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
			errorPortNumber(v)
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
		fmt.Println("bad input for port value")
		return
	}
	var (
		portFirst int
		portLast  int
	)
	convertStringToInt(ranges[0], &portFirst)
	errorPortNumber(portFirst)
	convertStringToInt(ranges[1], &portLast)
	errorPortNumber(portLast)
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
		fmt.Println("bad input for port value: " + err.Error())
		return
	}
	*v = va
}

func errorPortNumber(p int) {
	if p > 65535 || p < 0 {
		fmt.Println("bad input for port value")
		return
	}
}
