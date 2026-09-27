package binaryfmt

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Format identifies a recognised binary container format.
type Format string

const (
	FormatELF Format = "elf"
	FormatPE  Format = "pe"
)

// Class is the address width of a binary.
type Class string

const (
	Class32 Class = "ELF32"
	Class64 Class = "ELF64"
)

// Section describes one section of a parsed binary.
type Section struct {
	Name   string
	Size   uint64
	Offset uint64
}

// Info holds the structured facts extracted from a binary sample.
type Info struct {
	Format Format
	// Class is the address width (ELF32/ELF64; PE32/PE32+).
	Class Class
	// Machine is the target architecture as reported by the format header
	// (ELF e_machine / PE machine), rendered as a short string.
	Machine string
	// Subsystem is the PE subsystem (e.g. "console", "gui"); empty for ELF.
	Subsystem string
	Entry     uint64
	Sections  []Section
	// Stripped reports whether symbol/debug information appears to be absent.
	Stripped bool
	// Size is the total number of bytes that were parsed.
	Size int64
}

// HasSection reports whether a section with the given name is present.
func (i *Info) HasSection(name string) bool {
	for _, s := range i.Sections {
		if s.Name == name {
			return true
		}
	}
	return false
}

var (
	elfMagic = []byte{0x7f, 'E', 'L', 'F'}
	mzMagic  = []byte{'M', 'Z'}
	// Mach-O magic numbers, used to produce an explicit "unsupported" error
	// rather than a generic unrecognised-file error.
	machoMagic32  = []byte{0xfe, 0xed, 0xfa, 0xce}
	machoMagic64  = []byte{0xfe, 0xed, 0xfa, 0xcf}
	machoFatMagic = []byte{0xca, 0xfe, 0xba, 0xbe}
)

// Parse parses a binary read from r. name is used only for error context.
//
// Error classification:
//   - ReasonUnsupportedFormat: no recognisable container (empty file, random
//     data, or a known but unsupported format such as Mach-O);
//   - ReasonTruncated: a recognised header whose advertised structures run
//     past end of file;
//   - ReasonCorrupt: magic recognised but header fields invalid.
func Parse(name string, r io.ReaderAt, size int64) (*Info, error) {
	head := make([]byte, 0x40)
	n, err := readAt(r, 0, head)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, err
	}
	head = head[:n]

	switch {
	case n >= 4 && equal(head[:4], elfMagic):
		return parseELF(name, r, size)
	case n >= 2 && equal(head[:2], mzMagic):
		return parsePE(name, r, size)
	case n >= 4 && (equal(head[:4], machoMagic32) || equal(head[:4], machoMagic64) || equal(head[:4], machoFatMagic)):
		return nil, &ParseError{Reason: ReasonUnsupportedFormat, File: name, Offset: 0,
			Detail: "Mach-O binaries are not supported"}
	case n == 0:
		return nil, &ParseError{Reason: ReasonUnsupportedFormat, File: name, Offset: 0,
			Detail: "empty file: no format magic"}
	default:
		return nil, &ParseError{Reason: ReasonUnsupportedFormat, File: name, Offset: 0,
			Detail: fmt.Sprintf("unrecognised magic bytes % x", head[:min(4, n)])}
	}
}

func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// readAt reads len(buf) bytes from r at off. A short read yields
// io.ErrUnexpectedEOF so callers can map it to ReasonTruncated.
func readAt(r io.ReaderAt, off int64, buf []byte) (int, error) {
	n, err := r.ReadAt(buf, off)
	if err == io.EOF && n == len(buf) {
		return n, nil
	}
	if err == io.EOF {
		return n, io.ErrUnexpectedEOF
	}
	return n, err
}

// parseError is a small constructor used by the format-specific parsers.
func parseError(reason FailureReason, name string, off int64, format string, args ...any) error {
	return &ParseError{Reason: reason, File: name, Offset: off, Detail: fmt.Sprintf(format, args...)}
}

// byteOrder picks little/big endian from the ELF EI_DATA byte.
func byteOrder(tag byte) (binary.ByteOrder, error) {
	switch tag {
	case 1:
		return binary.LittleEndian, nil
	case 2:
		return binary.BigEndian, nil
	default:
		return nil, fmt.Errorf("invalid ELF data encoding %d", tag)
	}
}
