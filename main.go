package main

import (
	"Port-Scanner/argsparse"
	"fmt"
)

func main() {
	scan := argsparse.NewArgumentParser()
	fmt.Println(scan)
}
