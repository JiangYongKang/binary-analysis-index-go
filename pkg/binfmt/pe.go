package binfmt

import (
	"encoding/binary"
)

func parsePE(data []byte, name string) (*BinaryInfo, error) {
	if len(data) < 0x40 {
		return nil, &ParseError{Kind: FailureTruncated, Format: FormatPE, Offset: int64(len(data)),
			Context: "file shorter than DOS header (64 bytes)"}
	}
	bo := binary.LittleEndian
	peOff := int64(bo.Uint32(data[0x3c:]))
	if peOff+24 > int64(len(data)) {
		return nil, &ParseError{Kind: FailureTruncated, Format: FormatPE, Offset: 0x3c,
			Context: "e_lfanew points past end of file (COFF header unreachable)"}
	}
	if string(data[peOff:peOff+4]) != "PE\x00\x00" {
		return nil, &ParseError{Kind: FailureCorrupt, Format: FormatPE, Offset: peOff,
			Context: `missing "PE\\x00\\x00" signature at e_lfanew`}
	}
	coff := peOff + 4
	machine := bo.Uint16(data[coff+0:])
	numSections := int(bo.Uint16(data[coff+2:]))
	optSize := int(bo.Uint16(data[coff+16:]))
	opt := coff + 20
	if optSize == 0 {
		return nil, &ParseError{Kind: FailureUnsupported, Format: FormatPE, Offset: coff + 16,
			Context: "PE object without optional header is not a loadable image"}
	}
	if opt+int64(optSize) > int64(len(data)) {
		return nil, &ParseError{Kind: FailureTruncated, Format: FormatPE, Offset: opt,
			Context: "optional header extends past end of file"}
	}
	magic := bo.Uint16(data[opt:])
	var bits int
	var ddBase int64 // 数据目录表起始（紧跟 NumberOfRvaAndSizes 之后）
	var entryRVA uint32
	switch magic {
	case 0x20b: // PE32+
		bits = 64
		entryRVA = bo.Uint32(data[opt+16:])
		ddBase = opt + 112
	case 0x10b: // PE32
		bits = 32
		entryRVA = bo.Uint32(data[opt+16:])
		ddBase = opt + 96
	default:
		return nil, &ParseError{Kind: FailureCorrupt, Format: FormatPE, Offset: opt,
			Context: "unknown optional header magic (neither PE32 0x10b nor PE32+ 0x20b)"}
	}
	imageBase := uint64(0)
	if bits == 64 {
		imageBase = bo.Uint64(data[opt+24:])
	} else {
		imageBase = uint64(bo.Uint32(data[opt+28:]))
	}
	_ = imageBase

	// NumberOfRvaAndSizes：PE32+ 在 opt+108，PE32 在 opt+92；数据目录每项 8 字节
	numDDOff := ddBase - 4
	if numDDOff+4 > int64(len(data)) {
		return nil, &ParseError{Kind: FailureTruncated, Format: FormatPE, Offset: numDDOff,
			Context: "NumberOfRvaAndSizes field outside file"}
	}
	numDD := int(bo.Uint32(data[numDDOff:]))
	if ddBase+int64(numDD)*8 > int64(len(data)) {
		return nil, &ParseError{Kind: FailureTruncated, Format: FormatPE, Offset: ddBase,
			Context: "declared number of data directories extends past end of file"}
	}
	importRVA, importSize := uint32(0), uint32(0)
	if numDD >= 2 {
		importRVA = bo.Uint32(data[ddBase+8:])
		importSize = bo.Uint32(data[ddBase+12:])
	}

	sectOff := opt + int64(optSize)
	if sectOff+int64(numSections)*40 > int64(len(data)) {
		return nil, &ParseError{Kind: FailureTruncated, Format: FormatPE, Offset: sectOff,
			Context: "section table extends past end of file"}
	}
	type peSec struct {
		name                          string
		vaddr, vsize, rawOff, rawSize uint32
		chars                         uint32
	}
	sects := make([]peSec, 0, numSections)
	secTab := make([]Section, 0, numSections)
	for i := 0; i < numSections; i++ {
		b := sectOff + int64(i*40)
		nm := cstring(data[b : b+8])
		vsize := bo.Uint32(data[b+8:])
		vaddr := bo.Uint32(data[b+12:])
		rawSize := bo.Uint32(data[b+16:])
		rawOff := bo.Uint32(data[b+20:])
		chars := bo.Uint32(data[b+36:])
		if uint64(rawOff)+uint64(rawSize) > uint64(len(data)) {
			return nil, &ParseError{Kind: FailureTruncated, Format: FormatPE, Offset: int64(rawOff),
				Context: "section " + nm + " raw data extends past end of file"}
		}
		raw := data[rawOff : uint64(rawOff)+uint64(rawSize)]
		sects = append(sects, peSec{nm, vaddr, vsize, rawOff, rawSize, chars})
		sec := Section{Name: nm, Addr: uint64(vaddr), Size: uint64(vsize), Offset: uint64(rawOff),
			RawData: raw, Entropy: entropy(raw), Flags: uint64(chars)}
		if isUPXName(nm) {
			sec.IsUPXLike = true
		}
		secTab = append(secTab, sec)
	}

	rva2off := func(rva uint32) (int64, bool) {
		for _, s := range sects {
			if rva >= s.vaddr && rva < s.vaddr+maxu32(s.vsize, s.rawSize) {
				return int64(s.rawOff) + int64(rva-s.vaddr), true
			}
		}
		return 0, false
	}

	info := &BinaryInfo{
		Format:   FormatPE,
		Arch:     Arch(peMachineName(machine)),
		Bits:     bits,
		Endian:   "little",
		Type:     peImageType(bo.Uint16(data[coff+18:])),
		Entry:    uint64(entryRVA),
		Sections: secTab,
		Imports:  map[string][]string{},
		RawSize:  int64(len(data)),
	}

	if importRVA != 0 && importSize >= 20 {
		if err := parsePEImports(data, rva2off, info, importRVA, importSize); err != nil {
			return nil, err
		}
	}
	_ = name
	return info, nil
}

func parsePEImports(data []byte, rva2off func(uint32) (int64, bool), info *BinaryInfo, importRVA, importSize uint32) error {
	bo := binary.LittleEndian
	base, ok := rva2off(importRVA)
	if !ok {
		return &ParseError{Kind: FailureCorrupt, Format: FormatPE, Offset: int64(importRVA),
			Context: "import directory RVA does not lie in any section"}
	}
	// 每个 IMAGE_IMPORT_DESCRIPTOR 20 字节；描述符区域只读到全零终止项之前，
	// 终止项（无论是否计入 importSize）都通过“全零即结束”规则处理。
	limit := int64(importSize) - 20
	for i := int64(0); i <= limit; i += 20 {
		d := base + i
		if d+20 > int64(len(data)) {
			return &ParseError{Kind: FailureTruncated, Format: FormatPE, Offset: d,
				Context: "import descriptor extends past end of file"}
		}
		ilt := bo.Uint32(data[d:])
		nameRVA := bo.Uint32(data[d+12:])
		iat := bo.Uint32(data[d+16:])
		// 描述符全零才是结束项；TimeDateStamp/ForwarderChain 合法情况下就是 0，
		// 不能因为 ILT/IAT/名称某一个为空就提前终止。
		if ilt == 0 && nameRVA == 0 && iat == 0 &&
			bo.Uint32(data[d+4:]) == 0 && bo.Uint32(data[d+8:]) == 0 {
			break
		}
		if nameRVA == 0 {
			return &ParseError{Kind: FailureCorrupt, Format: FormatPE, Offset: d + 12,
				Context: "import descriptor has zero Name RVA"}
		}
		nameOff, ok := rva2off(nameRVA)
		if !ok {
			return &ParseError{Kind: FailureCorrupt, Format: FormatPE, Offset: int64(nameRVA),
				Context: "import DLL name RVA not mapped"}
		}
		dll, err := readCStringAt(data, nameOff)
		if err != nil {
			return &ParseError{Kind: FailureTruncated, Format: FormatPE, Offset: nameOff,
				Context: "import DLL name not NUL-terminated within file", Err: err}
		}
		// PE32+ 的 ILT 项为 8 字节
		thunkRVA := ilt
		if thunkRVA == 0 {
			thunkRVA = iat
		}
		var funcs []string
		toff, ok := rva2off(thunkRVA)
		if !ok {
			return &ParseError{Kind: FailureCorrupt, Format: FormatPE, Offset: int64(thunkRVA),
				Context: "import lookup table RVA not mapped (DLL " + dll + ")"}
		}
		for {
			if info.Bits == 64 {
				if toff+8 > int64(len(data)) {
					return &ParseError{Kind: FailureTruncated, Format: FormatPE, Offset: toff,
						Context: "64-bit import thunk table truncated (DLL " + dll + ")"}
				}
				v := bo.Uint64(data[toff:])
				toff += 8
				if v == 0 {
					break
				}
				if v&(1<<63) != 0 { // ordinal
					funcs = append(funcs, ordinalName(v&0xffff))
					continue
				}
				hnOff, ok := rva2off(uint32(v))
				if !ok {
					return &ParseError{Kind: FailureCorrupt, Format: FormatPE, Offset: int64(v),
						Context: "import hint/name RVA not mapped (DLL " + dll + ")"}
				}
				s, err := readHintName(data, hnOff)
				if err != nil {
					return &ParseError{Kind: FailureTruncated, Format: FormatPE, Offset: hnOff,
						Context: "import hint/name truncated (DLL " + dll + ")", Err: err}
				}
				funcs = append(funcs, s)
			} else {
				if toff+4 > int64(len(data)) {
					return &ParseError{Kind: FailureTruncated, Format: FormatPE, Offset: toff,
						Context: "32-bit import thunk table truncated (DLL " + dll + ")"}
				}
				v := bo.Uint32(data[toff:])
				toff += 4
				if v == 0 {
					break
				}
				if v&(1<<31) != 0 {
					funcs = append(funcs, ordinalName(uint64(v&0xffff)))
					continue
				}
				hnOff, ok := rva2off(v)
				if !ok {
					return &ParseError{Kind: FailureCorrupt, Format: FormatPE, Offset: int64(v),
						Context: "import hint/name RVA not mapped (DLL " + dll + ")"}
				}
				s, err := readHintName(data, hnOff)
				if err != nil {
					return &ParseError{Kind: FailureTruncated, Format: FormatPE, Offset: hnOff,
						Context: "import hint/name truncated (DLL " + dll + ")", Err: err}
				}
				funcs = append(funcs, s)
			}
		}
		info.Imports[dll] = funcs
	}
	return nil
}

func readHintName(data []byte, off int64) (string, error) {
	// hint 占 2 字节，其后为 NUL 结尾的符号名
	if off+2 >= int64(len(data)) {
		return "", &ParseError{Kind: FailureTruncated, Format: FormatPE, Offset: off,
			Context: "hint/name outside file"}
	}
	return readCStringAt(data, off+2)
}

func readCStringAt(data []byte, off int64) (string, error) {
	for i := off; i < int64(len(data)); i++ {
		if data[i] == 0 {
			return string(data[off:i]), nil
		}
	}
	return "", &ParseError{Kind: FailureTruncated, Format: FormatPE, Offset: off,
		Context: "unterminated C string"}
}

func cstring(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func ordinalName(ord uint64) string {
	const hexd = "0123456789abcdef"
	if ord < 16 {
		return "#ord" + string(hexd[ord])
	}
	return ordinalName(ord/16) + string(hexd[ord%16])
}

func isUPXName(n string) bool {
	ln := lowerASCII(n)
	return hasPrefix(ln, "upx") || ln == ".upx" || contains(ln, "upx")
}

func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

func hasPrefix(s, p string) bool {
	return len(s) >= len(p) && s[:len(p)] == p
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func maxu32(a, b uint32) uint32 {
	if a > b {
		return a
	}
	return b
}

func peMachineName(m uint16) string {
	switch m {
	case 0x14c:
		return "x86"
	case 0x8664:
		return "amd64"
	case 0xaa64:
		return "arm64"
	default:
		return "unknown"
	}
}

func peImageType(characteristics uint16) string {
	if characteristics&0x2000 != 0 { // IMAGE_FILE_DLL
		return "dll"
	}
	return "exe"
}
