package main

import (
	"fmt"
	"os"
	"strings"
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
	version, err := machoDetect(f)
	if err == nil {
		goto done
	}
	if !strings.Contains(err.Error(), "invalid magic number") {
		fmt.Fprintln(os.Stderr, "unable to detect from macho:", err.Error())
		os.Exit(1)
	}
	version, err = elfDetect(f)
	if err == nil {
		goto done
	}
	if !strings.Contains(err.Error(), "bad magic number") {
		fmt.Fprintln(os.Stderr, "unable to detect from elf:", err.Error())
		os.Exit(1)
	}
	version, err = peDetect(f)
	if err != nil {
		// TODO: catch "bad magic number" error like above
		fmt.Fprintln(os.Stderr, "unable to detect from pe:", err.Error())
		os.Exit(1)
	}
done:
	fmt.Println(version)
}
