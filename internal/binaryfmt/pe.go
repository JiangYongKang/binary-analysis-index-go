package binaryfmt

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	peSignatureOffsetField = 0x3c
	peSignatureSize        = 4
	coffHeaderSize         = 20
	peSectionHeaderSize    = 40
)

// PE address-width labels supplement the ELF-oriented Class constants.
const (
	ClassPE32     Class = "PE32"
	ClassPE32Plus Class = "PE32+"
)

var peMachineNames = map[uint16]string{
	0x014c: "x86",
	0x01c0: "arm",
	0x0aa6: "aarch64",
	0x8664: "x86_64",
}

var peSubsystemNames = map[uint16]string{
	1: "native",
	2: "gui",
	3: "console",
}

// parsePE parses the DOS header, PE signature, COFF header, optional header
// and section table of a PE/COFF image.
func parsePE(name string, r io.ReaderAt, size int64) (*Info, error) {
	ord := binary.LittleEndian

	// DOS header must be large enough to hold e_lfanew.
	dos, err := readExact(name, r, 0, 0x40)
	if err != nil {
		return nil, err
	}
	if dos[0] != 'M' || dos[1] != 'Z' {
		return nil, &ParseError{Reason: ReasonCorrupt, File: name, Offset: 0,
			Detail: "DOS magic is not MZ"}
	}
	peOff := int64(ord.Uint32(dos[peSignatureOffsetField:]))
	if peOff <= 0 || peOff >= size {
		return nil, &ParseError{Reason: ReasonTruncated, File: name,
			Offset: peSignatureOffsetField,
			Detail: fmt.Sprintf("e_lfanew=%d points past end of file (size %d)", peOff, size)}
	}

	sig, err := readExact(name, r, peOff, peSignatureSize)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(sig, []byte{'P', 'E', 0, 0}) {
		return nil, &ParseError{Reason: ReasonCorrupt, File: name, Offset: peOff,
			Detail: fmt.Sprintf("expected PE\\0\\0 signature, got % x", sig)}
	}

	coffOff := peOff + peSignatureSize
	coff, err := readExact(name, r, coffOff, coffHeaderSize)
	if err != nil {
		return nil, err
	}
	machine := ord.Uint16(coff[0:2])
	numSections := ord.Uint16(coff[2:4])
	ptrSymbolTable := ord.Uint32(coff[8:12])
	numSymbols := ord.Uint32(coff[12:16])
	optHeaderSize := ord.Uint16(coff[16:18])

	optOff := coffOff + coffHeaderSize
	if optHeaderSize < 2 {
		return nil, &ParseError{Reason: ReasonCorrupt, File: name, Offset: coffOff + 16,
			Detail: fmt.Sprintf("SizeOfOptionalHeader=%d too small for a PE image", optHeaderSize)}
	}
	opt, err := readExact(name, r, optOff, int(optHeaderSize))
	if err != nil {
		return nil, err
	}

	info := &Info{Format: FormatPE, Size: size}
	switch magic := ord.Uint16(opt[0:2]); magic {
	case 0x10b:
		info.Class = ClassPE32
	case 0x20b:
		info.Class = ClassPE32Plus
	default:
		return nil, &ParseError{Reason: ReasonCorrupt, File: name, Offset: optOff,
			Detail: fmt.Sprintf("unknown PE optional-header magic 0x%04x", magic)}
	}

	// AddressOfEntryPoint is at optional-header offset 16 for both flavors.
	info.Entry = uint64(ord.Uint32(opt[16:20]))

	// Subsystem offset: PE32 -> 68, PE32+ -> 72.
	subsysOff := 68
	if info.Class == ClassPE32Plus {
		subsysOff = 72
	}
	if subsysOff+2 > len(opt) {
		return nil, &ParseError{Reason: ReasonTruncated, File: name, Offset: optOff + int64(subsysOff),
			Detail: "optional header too short to contain Subsystem"}
	}
	subsystem := ord.Uint16(opt[subsysOff : subsysOff+2])
	if s, ok := peSubsystemNames[subsystem]; ok {
		info.Subsystem = s
	} else {
		info.Subsystem = fmt.Sprintf("unknown(%d)", subsystem)
	}

	// Debug data directory is index 6. It starts at optional-header offset
	// 96 (PE32) or 112 (PE32+); each entry is 8 bytes.
	debugDirOff := 96
	if info.Class == ClassPE32Plus {
		debugDirOff = 112
	}
	hasDebugDir := false
	if debugDirOff+8 <= len(opt) {
		hasDebugDir = ord.Uint32(opt[debugDirOff:debugDirOff+4]) != 0
	}

	if m, ok := peMachineNames[machine]; ok {
		info.Machine = m
	} else {
		info.Machine = fmt.Sprintf("unknown(0x%x)", machine)
	}

	// COFF symbol table, if present, must fit in the file.
	if ptrSymbolTable != 0 {
		symBytes := int64(numSymbols) * 18
		if err := boundsCheck(name, size, int64(ptrSymbolTable), uint64(symBytes), "PE COFF symbol table"); err != nil {
			return nil, err
		}
	}
	info.Stripped = ptrSymbolTable == 0 && !hasDebugDir

	sectOff := optOff + int64(optHeaderSize)
	if err := boundsCheck(name, size, sectOff, uint64(numSections)*peSectionHeaderSize, "PE section table"); err != nil {
		return nil, err
	}
	for i := uint16(0); i < numSections; i++ {
		buf, err := readExact(name, r, sectOff+int64(i)*peSectionHeaderSize, peSectionHeaderSize)
		if err != nil {
			return nil, err
		}
		sname := cstring8(buf[0:8])
		rawSize := ord.Uint32(buf[16:20])
		rawPtr := ord.Uint32(buf[20:24])
		if rawPtr != 0 {
			if err := boundsCheck(name, size, int64(rawPtr), uint64(rawSize), "PE section raw data"); err != nil {
				return nil, err
			}
		}
		info.Sections = append(info.Sections, Section{
			Name:   sname,
			Offset: uint64(rawPtr),
			Size:   uint64(rawSize),
		})
	}

	return info, nil
}

// cstring8 reads a space-padded, NUL-terminated 8-byte PE section name.
func cstring8(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
