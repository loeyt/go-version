package main

import (
	"fmt"
	"os"
)

type str32 struct {
	Addr, Len uint32
}

type str64 struct {
	Addr, Len uint64
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: "+os.Args[0]+" path/to/executable")
		os.Exit(2)
	}
	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "could not open file:", err.Error())
		os.Exit(1)
	}
	version, err := elfDetect(f)
	if err != nil {
		fmt.Fprintln(os.Stderr, "unable to detect from elf:", err.Error())
		os.Exit(1)
	}
	fmt.Println(version)
}
