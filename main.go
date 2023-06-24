package main

import (
	"Port-Scanner/argsparse"
	ack "Port-Scanner/scanner/ack-scan"
	fin "Port-Scanner/scanner/fin-scan"
	null "Port-Scanner/scanner/null-scan"
	syn "Port-Scanner/scanner/syn-scan"
	tcp "Port-Scanner/scanner/tcp-scan"
	udp "Port-Scanner/scanner/udp-scan"
	window "Port-Scanner/scanner/window-scan"
	xmas "Port-Scanner/scanner/xmas-scan"
)

func main() {
	scan, t := argsparse.NewArgumentParser()
	switch t {
	case 0:
		syn.HandleSynScanMethod(scan)
		break
	case 1:
		fin.HandleFinScanMethod(scan)
		break
	case 2:
		xmas.HandleXmasScanMethod(scan)
		break
	case 3:
		null.HandleNullScanMethod(scan)
		break
	case 4:
		ack.HandleAckScanMethod(scan)
		break
	case 5:
		window.HandleWindowScanMethod(scan)
		break
	case 6:
		udp.HandleUdpScanMethod(scan)
		break
	case 7:
		tcp.HandleFullTcpScanMethod(scan)
		break
	}
}
