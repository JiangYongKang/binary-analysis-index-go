package samples

import (
	"encoding/binary"
)

// elfWriter builds a minimal little-endian ELF64 object from a list of
// sections. Only what the parser consumes is populated.
//
// File layout: ELF header (64B) | section data (in order) | .shstrtab data |
// section-header table (null section + user sections + .shstrtab).
type elfSection struct {
	name string
	typ  uint32
	data []byte
}

type elfWriter struct {
	sections []elfSection
}

func (w *elfWriter) bytes() []byte {
	// Section 0 is the null section.
	names := []string{""}
	for _, s := range w.sections {
		names = append(names, s.name)
	}

	// Build the section-header string table (.shstrtab).
	var strtab []byte
	strtab = append(strtab, 0)
	nameOff := map[string]uint32{"": 0}
	for _, nm := range names[1:] {
		nameOff[nm] = uint32(len(strtab))
		strtab = append(strtab, []byte(nm)...)
		strtab = append(strtab, 0)
	}

	const ehSize = 64
	const shSize = 64

	type laid struct {
		s    elfSection
		off  uint64
		size uint64
	}
	cursor := uint64(ehSize)
	var laidOut []laid
	for _, s := range w.sections {
		laidOut = append(laidOut, laid{s: s, off: cursor, size: uint64(len(s.data))})
		cursor += uint64(len(s.data))
	}
	strOff := cursor
	strSize := uint64(len(strtab))
	shTableOff := strOff + strSize

	numSections := uint16(len(w.sections) + 2) // null + user + .shstrtab
	shstrIdx := uint16(len(w.sections) + 1)
	totalSize := shTableOff + uint64(numSections)*shSize
	b := make([]byte, totalSize)

	put := func(off uint64, p []byte) { copy(b[off:], p) }
	put16 := func(off uint64, v uint16) {
		var buf [2]byte
		binary.LittleEndian.PutUint16(buf[:], v)
		put(off, buf[:])
	}
	put32 := func(off uint64, v uint32) {
		var buf [4]byte
		binary.LittleEndian.PutUint32(buf[:], v)
		put(off, buf[:])
	}
	put64 := func(off uint64, v uint64) {
		var buf [8]byte
		binary.LittleEndian.PutUint64(buf[:], v)
		put(off, buf[:])
	}

	// ELF header.
	put(0, []byte{0x7f, 'E', 'L', 'F'})
	b[4] = 2               // EI_CLASS: 64-bit
	b[5] = 1               // EI_DATA: little endian
	b[6] = 1               // EI_VERSION
	b[7] = 0               // EI_OSABI: SYSV
	put16(16, 1)           // e_type: ET_REL
	put16(18, 0x3e)        // e_machine: x86_64
	put32(20, 1)           // e_version
	put64(24, 0)           // e_entry
	put64(32, 0)           // e_phoff
	put64(40, shTableOff)  // e_shoff
	put32(48, 0)           // e_flags
	put16(52, ehSize)      // e_ehsize
	put16(54, 0)           // e_phentsize
	put16(56, 0)           // e_phnum
	put16(58, shSize)      // e_shentsize
	put16(60, numSections) // e_shnum
	put16(62, shstrIdx)    // e_shstrndx

	// User section data and .shstrtab data.
	for _, l := range laidOut {
		put(l.off, l.s.data)
	}
	put(strOff, strtab)

	// Section headers.
	sh := func(idx uint16, name string, typ uint32, off, size uint64) {
		base := shTableOff + uint64(idx)*shSize
		put32(base+0, nameOff[name])
		put32(base+4, typ)
		put64(base+24, off)
		put64(base+32, size)
	}
	sh(shstrIdx, ".shstrtab", 3, strOff, strSize) // SHT_STRTAB
	for i, l := range laidOut {
		sh(uint16(i+1), l.s.name, l.s.typ, l.off, l.size)
	}

	return b
}

// buildELF writes an ELF64 containing .shstrtab plus the given sections.
func buildELF(extra ...elfSection) []byte {
	w := &elfWriter{sections: extra}
	return w.bytes()
}
