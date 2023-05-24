package main

import (
	"Port-Scanner/argsparse"
)

func main() {
	scan, t := argsparse.NewArgumentParser()
	scan.HandleScan(t)
}
