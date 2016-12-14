package main

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
)

func elfDetect(r io.ReaderAt) (string, error) {
	f, err := elf.NewFile(r)
	if err != nil {
		return "", err
	}
	symbols, err := f.Symbols()
	if err != nil {
		return "", err
	}
	var symbol *elf.Symbol
	for s := range symbols {
		if symbols[s].Name == "runtime.buildVersion" {
			symbol = &symbols[s]
		}
	}
	if symbol == nil {
		return "", fmt.Errorf("runtime.buildVersion not found, not a Go binary?")
	}
	var str interface{}
	switch f.Class {
	case elf.ELFCLASS32:
		str = &str32{}
	case elf.ELFCLASS64:
		str = &str64{}
	default:
		return "", fmt.Errorf("unknown elf class: %d\n", f.Class)
	}
	sr, err := openElf(f, symbol.Value)
	if err != nil {
		return "", err
	}
	err = binary.Read(sr, f.ByteOrder, str)
	if err != nil {
		return "", err
	}
	var (
		straddr uint64
		strlen  uint64
	)
	switch f.Class {
	case elf.ELFCLASS32:
		straddr, strlen = uint64(str.(*str32).Addr), uint64(str.(*str32).Len)
	case elf.ELFCLASS64:
		straddr, strlen = str.(*str64).Addr, str.(*str64).Len
	}
	sr, err = openElf(f, straddr)
	if err != nil {
		return "", err
	}
	data := make([]byte, strlen)
	_, err = io.ReadFull(sr, data)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func openElf(f *elf.File, addr uint64) (io.ReadSeeker, error) {
	for _, section := range f.Sections {
		if addr >= section.Addr && addr < section.Addr+section.Size {
			r := section.Open()
			_, err := r.Seek(int64(addr-section.Addr), io.SeekCurrent)
			return r, err
		}
	}
	return nil, nil
}
