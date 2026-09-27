package binaryfmt

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// readExact returns n bytes from r at off, classifying a short read as a
// truncated-file error anchored at off.
func readExact(name string, r io.ReaderAt, off int64, n int) ([]byte, error) {
	if off < 0 || n < 0 || off > maxOffset-int64(n) {
		return nil, &ParseError{Reason: ReasonCorrupt, File: name, Offset: off,
			Detail: "offset/length out of int64 range"}
	}
	buf := make([]byte, n)
	if _, err := readAt(r, off, buf); err != nil {
		if err == io.ErrUnexpectedEOF || err == io.EOF {
			return nil, &ParseError{Reason: ReasonTruncated, File: name, Offset: off,
				Detail: fmt.Sprintf("needed %d bytes for an ELF structure", n)}
		}
		return nil, err
	}
	return buf, nil
}

const maxOffset = int64(^uint64(0) >> 1)

// elfMachineNames maps the e_machine values we care about.
var elfMachineNames = map[uint16]string{
	0x03: "x86",
	0x28: "arm",
	0x3e: "x86_64",
	0xb7: "aarch64",
	0xf3: "riscv64",
}

// parseELF parses the ELF identification, header and section headers.
func parseELF(name string, r io.ReaderAt, size int64) (*Info, error) {
	const (
		eh32Size = 52
		eh64Size = 64
		sh32Size = 40
		sh64Size = 64
	)

	ident, err := readExact(name, r, 0, 16)
	if err != nil {
		return nil, err
	}
	is64 := false
	switch ident[4] { // EI_CLASS
	case 1:
		is64 = false
	case 2:
		is64 = true
	default:
		return nil, &ParseError{Reason: ReasonCorrupt, File: name, Offset: 4,
			Detail: fmt.Sprintf("invalid EI_CLASS=%d (expected 1 or 2)", ident[4])}
	}
	if ident[6] != 1 { // EI_VERSION
		return nil, &ParseError{Reason: ReasonCorrupt, File: name, Offset: 6,
			Detail: fmt.Sprintf("invalid EI_VERSION=%d (expected 1)", ident[6])}
	}
	ord, err := byteOrder(ident[5])
	if err != nil {
		return nil, &ParseError{Reason: ReasonCorrupt, File: name, Offset: 5, Detail: err.Error()}
	}

	ehSize := eh32Size
	if is64 {
		ehSize = eh64Size
	}
	eh, err := readExact(name, r, 0, ehSize)
	if err != nil {
		return nil, err
	}
	br := bytes.NewReader(eh)
	read := func(data any) {
		if err == nil {
			err = binary.Read(br, ord, data)
		}
	}

	info := &Info{Format: FormatELF, Size: size}
	if is64 {
		info.Class = Class64
	} else {
		info.Class = Class32
	}

	var machine uint16
	if is64 {
		br.Seek(16, io.SeekStart)
		var eType uint16
		read(&eType)
		read(&machine)
		var eVersion uint32
		read(&eVersion)
		var entry uint64
		read(&entry)
		info.Entry = entry
		var phoff, shoff uint64
		read(&phoff)
		read(&shoff)
		read(&eVersion) // e_flags
		var ehsize, phentsize, phnum, shentsize, shnum, shstrndx uint16
		read(&ehsize)
		read(&phentsize)
		read(&phnum)
		read(&shentsize)
		read(&shnum)
		read(&shstrndx)
		if err != nil {
			return nil, &ParseError{Reason: ReasonCorrupt, File: name, Offset: 0, Detail: "malformed ELF64 header"}
		}
		sections, err2 := readELFSections64(name, r, size, ord, int64(shoff), shnum, shstrndx)
		if err2 != nil {
			return nil, err2
		}
		info.Sections = sections
	} else {
		br.Seek(16, io.SeekStart)
		var eType uint16
		read(&eType)
		read(&machine)
		var eVersion uint32
		read(&eVersion)
		var entry, phoff, shoff uint32
		read(&entry)
		info.Entry = uint64(entry)
		read(&phoff)
		read(&shoff)
		var flags, ehsize, phentsize, phnum, shentsize, shnum, shstrndx uint32
		read(&flags)
		read(&ehsize)
		read(&phentsize)
		read(&phnum)
		read(&shentsize)
		read(&shnum)
		read(&shstrndx)
		if err != nil {
			return nil, &ParseError{Reason: ReasonCorrupt, File: name, Offset: 0, Detail: "malformed ELF32 header"}
		}
		sections, err2 := readELFSections32(name, r, size, ord, int64(shoff), uint16(shnum), uint16(shstrndx))
		if err2 != nil {
			return nil, err2
		}
		info.Sections = sections
	}

	if m, ok := elfMachineNames[machine]; ok {
		info.Machine = m
	} else {
		info.Machine = fmt.Sprintf("unknown(0x%x)", machine)
	}
	info.Stripped = !info.HasSection(".symtab")
	return info, nil
}

type elfSectionRaw struct {
	nameOff uint32
	offset  uint64
	size    uint64
}

// boundsCheck verifies that [off, off+n) lies within the file.
func boundsCheck(name string, size int64, off int64, n uint64, what string) error {
	if off < 0 || uint64(off) > uint64(size) {
		return &ParseError{Reason: ReasonTruncated, File: name, Offset: off,
			Detail: fmt.Sprintf("%s offset %d is outside the file", what, off)}
	}
	if uint64(size)-uint64(off) < n {
		return &ParseError{Reason: ReasonTruncated, File: name, Offset: off,
			Detail: fmt.Sprintf("%s (%d bytes) runs past end of file (size %d)", what, n, size)}
	}
	return nil
}

func readELFSections64(name string, r io.ReaderAt, size int64, ord binary.ByteOrder,
	shoff int64, shnum, shstrndx uint16,
) ([]Section, error) {
	if shoff == 0 || shnum == 0 {
		return nil, nil // no section headers: legal, treated as stripped
	}
	if int64(shstrndx) >= int64(shnum) {
		return nil, &ParseError{Reason: ReasonCorrupt, File: name, Offset: shoff,
			Detail: fmt.Sprintf("e_shstrndx=%d is not below e_shnum=%d", shstrndx, shnum)}
	}
	if err := boundsCheck(name, size, shoff, uint64(shnum)*64, "ELF section header table"); err != nil {
		return nil, err
	}
	raws := make([]elfSectionRaw, shnum)
	for i := range raws {
		buf, err := readExact(name, r, shoff+int64(i)*64, 64)
		if err != nil {
			return nil, err
		}
		raws[i] = elfSectionRaw{
			nameOff: ord.Uint32(buf[0:4]),
			offset:  ord.Uint64(buf[24:32]),
			size:    ord.Uint64(buf[32:40]),
		}
		if err := boundsCheck(name, size, int64(raws[i].offset), raws[i].size, "ELF section"); err != nil {
			return nil, err
		}
	}
	return nameELFSections(name, r, size, raws, shstrndx)
}

func readELFSections32(name string, r io.ReaderAt, size int64, ord binary.ByteOrder,
	shoff int64, shnum, shstrndx uint16,
) ([]Section, error) {
	if shoff == 0 || shnum == 0 {
		return nil, nil
	}
	if int64(shstrndx) >= int64(shnum) {
		return nil, &ParseError{Reason: ReasonCorrupt, File: name, Offset: shoff,
			Detail: fmt.Sprintf("e_shstrndx=%d is not below e_shnum=%d", shstrndx, shnum)}
	}
	if err := boundsCheck(name, size, shoff, uint64(shnum)*40, "ELF section header table"); err != nil {
		return nil, err
	}
	raws := make([]elfSectionRaw, shnum)
	for i := range raws {
		buf, err := readExact(name, r, shoff+int64(i)*40, 40)
		if err != nil {
			return nil, err
		}
		raws[i] = elfSectionRaw{
			nameOff: ord.Uint32(buf[0:4]),
			offset:  uint64(ord.Uint32(buf[16:20])),
			size:    uint64(ord.Uint32(buf[20:24])),
		}
		if err := boundsCheck(name, size, int64(raws[i].offset), raws[i].size, "ELF section"); err != nil {
			return nil, err
		}
	}
	return nameELFSections(name, r, size, raws, shstrndx)
}

func nameELFSections(name string, r io.ReaderAt, size int64, raws []elfSectionRaw, shstrndx uint16) ([]Section, error) {
	str := raws[shstrndx]
	strtab, err := readExact(name, r, int64(str.offset), int(str.size))
	if err != nil {
		return nil, err
	}
	out := make([]Section, 0, len(raws))
	for idx, raw := range raws {
		nm, err := cstring(strtab, raw.nameOff)
		if err != nil {
			return nil, &ParseError{Reason: ReasonCorrupt, File: name,
				Offset: int64(str.offset) + int64(raw.nameOff),
				Detail: fmt.Sprintf("section %d name offset outside .shstrtab", idx)}
		}
		out = append(out, Section{Name: nm, Offset: raw.offset, Size: raw.size})
	}
	return out, nil
}

// cstring extracts a NUL-terminated string starting at off.
func cstring(b []byte, off uint32) (string, error) {
	if int(off) >= len(b) {
		return "", fmt.Errorf("offset %d beyond string table of %d", off, len(b))
	}
	for i := int(off); i < len(b); i++ {
		if b[i] == 0 {
			return string(b[off:i]), nil
		}
	}
	return "", fmt.Errorf("unterminated string at offset %d", off)
}
