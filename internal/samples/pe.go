package samples

import "encoding/binary"

// peOptions controls the synthetic PE image.
type peOptions struct {
	subsystem uint16 // IMAGE_SUBSYSTEM_*
	// includeDebugDir emits a non-empty debug data-directory entry.
	includeDebugDir bool
	// includeCOFFSymbols emits a (dummy) COFF symbol table pointer.
	includeCOFFSymbols bool
}

// buildPE builds a minimal PE32+ image with one .text section.
func buildPE(o peOptions) []byte {
	const (
		dosSize  = 0x40
		sigSize  = 4
		coffSize = 20
		optSize  = 240 // generous fixed-size optional header + data directories
		sectSize = 40
		textSize = 16
	)
	headersSize := dosSize + sigSize + coffSize + optSize + sectSize
	textOff := uint32(headersSize)
	peOff := uint32(dosSize)
	coffOff := peOff + sigSize
	optOff := coffOff + coffSize

	b := make([]byte, headersSize+textSize)
	le := binary.LittleEndian

	// DOS header.
	b[0], b[1] = 'M', 'Z'
	le.PutUint32(b[0x3c:], peOff)

	// PE signature.
	b[peOff+0], b[peOff+1], b[peOff+2], b[peOff+3] = 'P', 'E', 0, 0

	// COFF header.
	c := b[coffOff:]
	le.PutUint16(c[0:], 0x8664) // machine: AMD64
	le.PutUint16(c[2:], 1)      // NumberOfSections
	le.PutUint32(c[4:], 0)      // TimeDateStamp
	if o.includeCOFFSymbols {
		// Point at the end of file; the data itself is irrelevant because the
		// parser only validates that the declared table fits.
		le.PutUint32(c[8:], uint32(len(b))-18)
		le.PutUint32(c[12:], 0)
	}
	le.PutUint16(c[16:], optSize) // SizeOfOptionalHeader
	le.PutUint16(c[18:], 0x22)    // Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

	// Optional header (PE32+).
	p := b[optOff:]
	le.PutUint16(p[0:], 0x20b)                // Magic: PE32+
	p[2] = 14                                 // MajorLinkerVersion
	p[3] = 0                                  // MinorLinkerVersion
	le.PutUint32(p[4:], textSize)             // SizeOfCode
	le.PutUint32(p[16:], 0x1000)              // AddressOfEntryPoint (RVA)
	le.PutUint32(p[20:], 0x1000)              // BaseOfCode
	le.PutUint64(p[24:], 0x140000000)         // ImageBase
	le.PutUint32(p[32:], 0x1000)              // SectionAlignment
	le.PutUint32(p[36:], 0x200)               // FileAlignment
	le.PutUint16(p[40:], 6)                   // MajorOperatingSystemVersion
	le.PutUint16(p[44:], 0)                   // MajorImageVersion
	le.PutUint16(p[48:], 6)                   // MajorSubsystemVersion
	le.PutUint32(p[56:], textSize)            // SizeOfImage-ish / SizeOfHeaders region
	le.PutUint32(p[60:], uint32(headersSize)) // SizeOfHeaders
	// Subsystem for PE32+ lives at optional-header offset 68/72 -> 72.
	le.PutUint16(p[72:], o.subsystem)
	// Data directories start at PE32+ offset 112; debug directory is index 6.
	if o.includeDebugDir {
		dd := 112 + 6*8
		le.PutUint32(p[dd:], 0x3000) // non-zero RVA -> debug info present
		le.PutUint32(p[dd+4:], 28)
	}

	// Section table: one .text section with raw data at EOF region.
	s := b[optOff+optSize:]
	copy(s[0:8], []byte{'.', 't', 'e', 'x', 't', 0, 0, 0})
	le.PutUint32(s[8:], textSize)         // VirtualSize
	le.PutUint32(s[12:], 0x1000)          // VirtualAddress
	le.PutUint32(s[16:], textSize)        // SizeOfRawData
	le.PutUint32(s[20:], uint32(textOff)) // PointerToRawData
	le.PutUint32(s[36:], 0x60000020)      // Characteristics: code|exec|read

	// Some raw .text bytes (halt instructions).
	for i := headersSize; i < headersSize+textSize; i++ {
		b[i] = 0xf4
	}
	return b
}
