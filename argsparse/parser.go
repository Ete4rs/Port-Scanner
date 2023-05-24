package argsparse

import (
	"flag"
	"fmt"
	"net"
	"strconv"
	"strings"
)

type Scan struct {
	Network *net.IPNet
	Port    Port
}

type Port struct {
	Single  []int
	Range   [][]int
	Exclude []int
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
	target := flag.String("target", "", "target(for example : 1.1.1.1/24")
	port := flag.String("port", "80", "target port")
	help := flag.Bool("help", false, "Show help")
	flag.Parse()
	if *help {
		flag.PrintDefaults()
		return nil
	}
	if false {
		fmt.Println(target, synScan, tcpConnectScan, finScan, xmasScan, nullScan, ackScan, windowScan, udpScan)
	}
	//ip, net, err := net.ParseCIDR(*target)
	//if err != nil {
	//	fmt.Printf("wrong input in ip/mask : %s\nplease use -help", *target)
	//	return nil
	//}
	scan := Scan{}
	parsePort(*port, &scan)
	fmt.Println(scan)
	return nil
}

func parsePort(port string, scan *Scan) {
	if strings.Contains(port, ",") {
		p := strings.Split(port, ",")
		for i := 0; i < len(p); i++ {
			if strings.Contains(p[i], "-") {
				parseRangePort(p[i], scan)
			} else {
				var v int
				convertStringToInt(p[i], &v)
				scan.Port.Single = append(scan.Port.Single, v)
			}
		}
	} else if strings.Contains(port, "-") {
		parseRangePort(port, scan)
	} else {
		var p int
		convertStringToInt(port, &p)
		scan.Port.Single = append(scan.Port.Single, p)
	}
}

func parseRangePort(p string, scan *Scan) {
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
	scan.Port.Range = append(scan.Port.Range, r)
}

func convertStringToInt(value string, v *int) {
	va, err := strconv.Atoi(value)
	if err != nil {
		fmt.Println("bad input for port")
		return
	}
	*v = va
}
