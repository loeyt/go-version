package main

import (
	"debug/macho"
	"encoding/binary"
	"fmt"
	"io"
)

func machoDetect(r io.ReaderAt) (string, error) {
	f, err := macho.NewFile(r)
	if err != nil {
		return "", err
	}
	var symbol *macho.Symbol
	for s := range f.Symtab.Syms {
		if f.Symtab.Syms[s].Name == "runtime.buildVersion" {
			symbol = &f.Symtab.Syms[s]
		}
	}
	if symbol == nil {
		return "", fmt.Errorf("runtime.buildVersion not found, not a Go binary?")
	}
	var str interface{}
	// macho.cpuArch64 = 0x01000000
	if f.Cpu&0x01000000 != 0 {
		str = &str64{}
	} else {
		str = &str32{}
	}
	sr, err := openMacho(f, symbol.Value)
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
	if f.Cpu&0x01000000 != 0 {
		straddr, strlen = str.(*str64).Addr, str.(*str64).Len
	} else {
		straddr, strlen = uint64(str.(*str32).Addr), uint64(str.(*str32).Len)
	}
	sr, err = openMacho(f, straddr)
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

func openMacho(f *macho.File, addr uint64) (io.ReadSeeker, error) {
	for _, section := range f.Sections {
		if addr >= section.Addr && addr < section.Addr+section.Size {
			r := section.Open()
			_, err := r.Seek(int64(addr-section.Addr), io.SeekCurrent)
			return r, err
		}
	}
	return nil, nil
}
