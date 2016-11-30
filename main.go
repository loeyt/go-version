package main

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: "+os.Args[0]+" path/to/executable")
		os.Exit(1)
	}
	f, err := elf.Open(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	symbols, err := f.Symbols()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var symbol *elf.Symbol
	for s := range symbols {
		if symbols[s].Name == "runtime.buildVersion" {
			symbol = &symbols[s]
		}
	}
	if symbol == nil {
		fmt.Fprintln(os.Stdout, "runtime.buildVersion not found, not a Go binary?")
		os.Exit(2)
	}
	r, err := open(f, symbol.Value)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var str struct {
		Addr, Len uint64
	}
	err = binary.Read(r, binary.LittleEndian, &str)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	r, err = open(f, str.Addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	data := make([]byte, str.Len)
	_, err = io.ReadFull(r, data)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(string(data))
}

func open(f *elf.File, addr uint64) (io.ReadSeeker, error) {
	for _, section := range f.Sections {
		if addr >= section.Addr && addr < section.Addr+section.Size {
			r := section.Open()
			_, err := r.Seek(int64(addr-section.Addr), io.SeekCurrent)
			return r, err
		}
	}
	return nil, nil
}
