// Package samples builds small, synthetic binary files for tests: valid ELF
// and PE executables written from scratch, plus truncated, corrupt and
// unsupported variants. No external tools or real samples are needed.
package samples

import "os"

// Set groups the on-disk paths of generated samples.
type Set struct {
	Dir string

	ELFStripped string
	ELFDebug    string
	PEConsole   string
	PEGUI       string
	PEStripped  string

	ELFTruncated  string
	PETruncated   string
	CorruptMagic  string
	CorruptHeader string
	Unsupported   string
	Empty         string
}

// Create generates every sample below dir and returns their paths.
func Create(dir string) (*Set, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	s := &Set{Dir: dir}
	p := func(name string) string { return dir + string(os.PathSeparator) + name }

	s.ELFStripped = p("elf_stripped.bin")
	s.ELFDebug = p("elf_debug.bin")
	s.PEConsole = p("pe_console.exe")
	s.PEGUI = p("pe_gui.exe")
	s.PEStripped = p("pe_stripped.exe")
	s.ELFTruncated = p("elf_truncated.bin")
	s.PETruncated = p("pe_truncated.exe")
	s.CorruptMagic = p("corrupt_magic.bin")
	s.CorruptHeader = p("corrupt_header.bin")
	s.Unsupported = p("macho_sample.bin")
	s.Empty = p("empty.bin")

	type job struct {
		path string
		fn   func(string) error
	}
	jobs := []job{
		{s.ELFStripped, WriteELFStripped},
		{s.ELFDebug, WriteELFDebug},
		{s.PEConsole, WritePEConsole},
		{s.PEGUI, WritePEGUI},
		{s.PEStripped, WritePEStripped},
		{s.ELFTruncated, WriteELFTruncated},
		{s.PETruncated, WritePETruncated},
		{s.CorruptMagic, WriteCorruptMagic},
		{s.CorruptHeader, WriteCorruptHeader},
		{s.Unsupported, WriteUnsupported},
		{s.Empty, WriteEmpty},
	}
	for _, j := range jobs {
		if err := j.fn(j.path); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// WriteELFStripped writes a minimal 64-bit ELF with no symbol table.
func WriteELFStripped(path string) error {
	// .note section present, but no .symtab: parser reports Stripped.
	data := buildELF(elfSection{name: ".note", typ: 7, data: []byte("NOTE\x00")})
	return writeFile(path, data)
}

// WriteELFDebug writes a minimal 64-bit ELF containing a .symtab section.
func WriteELFDebug(path string) error {
	data := buildELF(
		elfSection{name: ".note", typ: 7, data: []byte("NOTE\x00")},
		elfSection{name: ".symtab", typ: 2, data: make([]byte, 24)},
		elfSection{name: ".strtab", typ: 3, data: append([]byte{0}, []byte("sym\x00")...)},
	)
	return writeFile(path, data)
}

// WritePEConsole writes a minimal PE32+ executable with console subsystem.
func WritePEConsole(path string) error {
	return writeFile(path, buildPE(peOptions{subsystem: 3, includeDebugDir: true, includeCOFFSymbols: true}))
}

// WritePEGUI writes a minimal PE32+ executable with GUI subsystem.
func WritePEGUI(path string) error {
	return writeFile(path, buildPE(peOptions{subsystem: 2, includeDebugDir: true, includeCOFFSymbols: true}))
}

// WritePEStripped writes a minimal PE32+ with the debug directory and COFF
// symbol table absent.
func WritePEStripped(path string) error {
	return writeFile(path, buildPE(peOptions{subsystem: 3}))
}

// WriteELFTruncated writes a valid ELF header whose section headers point
// past end of file, then cuts most of the file away.
func WriteELFTruncated(path string) error {
	data := buildELF(elfSection{name: ".note", typ: 7, data: []byte("NOTE\x00")})
	// Keep the ELF header only: e_shoff points well past the truncation.
	return writeFile(path, data[:64])
}

// WritePETruncated writes a PE whose DOS header points at a PE header beyond
// the end of the file.
func WritePETruncated(path string) error {
	data := buildPE(peOptions{subsystem: 3})
	// Repoint e_lfanew at an offset beyond the file, then cut the file.
	copy(data[0x3c:0x40], []byte{0xff, 0xff, 0x00, 0x00})
	return writeFile(path, data[:0x40])
}

// WriteCorruptMagic writes random bytes that match no known magic.
func WriteCorruptMagic(path string) error {
	return writeFile(path, []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})
}

// WriteCorruptHeader writes bytes with an ELF magic but invalid header
// fields (bad EI_CLASS), i.e. structurally corrupt rather than truncated.
func WriteCorruptHeader(path string) error {
	data := make([]byte, 64)
	copy(data[0:4], []byte{0x7f, 'E', 'L', 'F'})
	data[4] = 9 // invalid EI_CLASS
	data[5] = 1
	data[6] = 1
	return writeFile(path, data)
}

// WriteUnsupported writes a well-formed-but-unsupported binary (Mach-O magic).
func WriteUnsupported(path string) error {
	return writeFile(path, []byte{0xfe, 0xed, 0xfa, 0xce, 0, 0, 0, 0})
}

// WriteEmpty creates a zero-byte file.
func WriteEmpty(path string) error { return writeFile(path, []byte{}) }

func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o644)
}
