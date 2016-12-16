package main

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
)

func peDetect(r io.ReaderAt) (string, error) {
	f, err := pe.NewFile(r)
	if err != nil {
		return "", err
	}
	var symbol *pe.Symbol
	for s := range f.Symbols {
		if f.Symbols[s].Name == "runtime.buildVersion" {
			symbol = f.Symbols[s]
		}
	}
	if symbol == nil {
		return "", fmt.Errorf("runtime.buildVersion not found, not a Go binary?")
	}
	var str interface{}
	switch f.Machine {
	case pe.IMAGE_FILE_MACHINE_I386:
		str = &str32{}
	case pe.IMAGE_FILE_MACHINE_AMD64:
		str = &str64{}
	default:
		return "", fmt.Errorf("unknown pe machine: %d\n", f.Machine)
	}
	sr, err := openPe(f, symbol.Value+f.Sections[symbol.SectionNumber-1].VirtualAddress) // TODO: eh?
	if err != nil {
		return "", err
	}
	err = binary.Read(sr, binary.LittleEndian, str)
	if err != nil {
		return "", err
	}
	var (
		straddr uint32
		strlen  uint32
	)
	switch f.Machine {
	case pe.IMAGE_FILE_MACHINE_I386:
		straddr, strlen = str.(*str32).Addr, str.(*str32).Len
	case pe.IMAGE_FILE_MACHINE_AMD64:
		straddr, strlen = uint32(str.(*str64).Addr), uint32(str.(*str64).Len)
	}
	straddr -= 0x400000 // TODO: wha?
	sr, err = openPe(f, straddr)
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

func openPe(f *pe.File, addr uint32) (io.ReadSeeker, error) {
	for _, section := range f.Sections {
		if addr >= section.VirtualAddress && addr < section.VirtualAddress+section.VirtualSize {
			r := section.Open()
			_, err := r.Seek(int64(addr-section.VirtualAddress), io.SeekCurrent)
			return r, err
		}
	}
	return nil, fmt.Errorf("unable to find address 0x%x\n", addr)
}

var _ = []*pe.Section{
	&pe.Section{SectionHeader: pe.SectionHeader{Name: ".text",
		VirtualSize:     0x157ef6,
		VirtualAddress:  0x1000,
		Size:            0x158000,
		Offset:          0x600,
		Characteristics: 0x60000060}},
	&pe.Section{SectionHeader: pe.SectionHeader{Name: ".data",
		VirtualSize:     0x341e0,
		VirtualAddress:  0x159000,
		Size:            0x13800,
		Offset:          0x158600,
		Characteristics: 0xc0000040}},
	&pe.Section{SectionHeader: pe.SectionHeader{Name: ".debug_abbrev",
		VirtualSize:     0xff,
		VirtualAddress:  0x18e000,
		Size:            0x200,
		Offset:          0x16be00,
		Characteristics: 0x42000000}},
	&pe.Section{SectionHeader: pe.SectionHeader{Name: ".debug_line",
		VirtualSize:     0x22323,
		VirtualAddress:  0x18f000,
		Size:            0x22400,
		Offset:          0x16c000,
		Characteristics: 0x42000000}},
	&pe.Section{SectionHeader: pe.SectionHeader{Name: ".debug_frame",
		VirtualSize:     0x159b4,
		VirtualAddress:  0x1b2000,
		Size:            0x15a00,
		Offset:          0x18e400,
		Characteristics: 0x42000000}},
	&pe.Section{SectionHeader: pe.SectionHeader{Name: ".debug_pubnames",
		VirtualSize:     0x19c95,
		VirtualAddress:  0x1c8000,
		Size:            0x19e00,
		Offset:          0x1a3e00,
		Characteristics: 0x42000000}},
	&pe.Section{SectionHeader: pe.SectionHeader{Name: ".debug_pubtypes",
		VirtualSize:     0x9a3b,
		VirtualAddress:  0x1e2000,
		Size:            0x9c00,
		Offset:          0x1bdc00,
		Characteristics: 0x42000000}},
	&pe.Section{SectionHeader: pe.SectionHeader{Name: ".debug_aranges",
		VirtualSize:     0x30,
		VirtualAddress:  0x1ec000,
		Size:            0x200,
		Offset:          0x1c7800,
		Characteristics: 0x42000000}},
	&pe.Section{SectionHeader: pe.SectionHeader{Name: ".debug_info",
		VirtualSize:     0x5b513,
		VirtualAddress:  0x1ed000,
		Size:            0x5b600,
		Offset:          0x1c7a00,
		Characteristics: 0x42000000}},
	&pe.Section{SectionHeader: pe.SectionHeader{Name: ".idata",
		VirtualSize:     0x514,
		VirtualAddress:  0x249000,
		Size:            0x600,
		Offset:          0x223000,
		Characteristics: 0xc0000040}},
	&pe.Section{SectionHeader: pe.SectionHeader{Name: ".symtab",
		VirtualSize:     0x26138,
		VirtualAddress:  0x24a000,
		Size:            0x26200,
		Offset:          0x223600,
		Characteristics: 0x42000000}},
}
