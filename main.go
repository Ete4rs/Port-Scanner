package main

import (
	"Port-Scanner/argsparse"
	syn "Port-Scanner/scanner/syn-scan"
)

func main() {
	scan, t := argsparse.NewArgumentParser()
	scan.Number += len(scan.SingleIP)
	for i := 0; i < len(scan.Network); i++ {
		ones, bits := scan.Network[i].Mask.Size()
		hosts := 1 << uint(bits-ones)
		scan.Number += hosts - 2
	}
	switch t {
	case 0:
		syn.HandleSynScanMethod(scan)
		break
	}
}
