package binfmt

import (
	"encoding/binary"
	"math"
)

// elf 解析辅助结构，封装端序与位宽相关读取。
type elfReader struct {
	data   []byte
	bo     binary.ByteOrder
	class  byte // 1=32bit, 2=64bit
	errOff int64
}

func parseELF(data []byte, name string) (*BinaryInfo, error) {
	if len(data) < 16 {
		return nil, &ParseError{Kind: FailureTruncated, Format: FormatELF, Offset: int64(len(data)),
			Context: "e_ident shorter than 16 bytes"}
	}
	class := data[4]
	if class != 1 && class != 2 {
		return nil, &ParseError{Kind: FailureUnsupported, Format: FormatELF, Offset: 4,
			Context: "unsupported EI_CLASS (only ELFCLASS32/64 supported)"}
	}
	var bo binary.ByteOrder
	switch data[5] {
	case 1:
		bo = binary.LittleEndian
	case 2:
		bo = binary.BigEndian
	default:
		return nil, &ParseError{Kind: FailureCorrupt, Format: FormatELF, Offset: 5,
			Context: "invalid EI_DATA encoding"}
	}
	r := &elfReader{data: data, bo: bo, class: class, errOff: -1}
	info := &BinaryInfo{Format: FormatELF, Endian: map[bool]string{true: "little", false: "big"}[bo == binary.LittleEndian], RawSize: int64(len(data))}
	if class == 2 {
		info.Bits = 64
	} else {
		info.Bits = 32
	}

	ehSize := 52
	if class == 2 {
		ehSize = 64
	}
	if len(data) < ehSize {
		return nil, &ParseError{Kind: FailureTruncated, Format: FormatELF, Offset: int64(len(data)),
			Context: "file shorter than ELF header"}
	}

	info.Type = elfTypeName(r.u16(16))
	info.Arch = Arch(elfMachineName(r.u16(18)))
	if class == 2 {
		info.Entry = r.u64(24)
	} else {
		info.Entry = uint64(r.u32(24))
	}

	var shoff int64
	if class == 2 {
		shoff = int64(r.u64(40))
	} else {
		shoff = int64(r.u32(32))
	}
	// e_shentsize/e_shnum/e_shstrndx 在 32/64 位下偏移相同（58/60/62）
	shentsize := int(r.u16(58))
	shnum := int(r.u16(60))
	shstrndx := int(r.u16(62))
	if shnum == 0 {
		// 无节表的 ELF（典型的 strip 场景）仍可接受，只是没有结构化节信息
		info.Sections = []Section{}
		return info, nil
	}
	wantEnt := 64
	if class == 1 {
		wantEnt = 40
	}
	if shentsize < wantEnt {
		return nil, &ParseError{Kind: FailureCorrupt, Format: FormatELF, Offset: 58,
			Context: "e_shentsize smaller than fixed section header size"}
	}
	if shoff < 0 || uint64(shoff)+uint64(shnum)*uint64(shentsize) > uint64(len(data)) {
		return nil, &ParseError{Kind: FailureTruncated, Format: FormatELF, Offset: shoff,
			Context: "section header table extends past end of file"}
	}
	if shstrndx >= shnum {
		return nil, &ParseError{Kind: FailureCorrupt, Format: FormatELF, Offset: 62,
			Context: "e_shstrndx out of range"}
	}

	// 先取节名字符串表
	strtabOff, strtabSize := r.shField(shoff, shentsize, shstrndx, "offset", "size")
	strtab, err := r.slice(strtabOff, strtabSize)
	if err != nil {
		return nil, err
	}

	info.Sections = make([]Section, 0, shnum)
	for i := 0; i < shnum; i++ {
		base := shoff + int64(i*shentsize)
		nameIdx := r.u32(base + 0)
		var flags, addr, off, size uint64
		if class == 2 {
			flags = r.u64(base + 8)
			addr = r.u64(base + 16)
			off = r.u64(base + 24)
			size = r.u64(base + 32)
		} else {
			flags = uint64(r.u32(base + 8))
			addr = uint64(r.u32(base + 12))
			off = uint64(r.u32(base + 16))
			size = uint64(r.u32(base + 20))
		}
		name, perr := elfString(strtab, nameIdx)
		if perr != nil {
			return nil, &ParseError{Kind: FailureCorrupt, Format: FormatELF, Offset: base,
				Context: "section sh_name out of .shstrtab", Err: perr}
		}
		raw, perr := r.slice(int64(off), size)
		if perr != nil {
			// 节数据落盘部分超出文件：区分截断
			return nil, &ParseError{Kind: FailureTruncated, Format: FormatELF, Offset: int64(off),
				Context: "section " + name + " data extends past end of file", Err: perr}
		}
		sec := Section{
			Name:    name,
			Size:    size,
			Addr:    addr,
			Offset:  off,
			Flags:   flags,
			RawData: raw,
			Entropy: entropy(raw),
		}
		ln := lowerASCII(name)
		if hasPrefix(ln, "upx") || ln == ".upx" || contains(ln, "upx") {
			sec.IsUPXLike = true
		}
		info.Sections = append(info.Sections, sec)
	}

	// DT_NEEDED（尽力而为：动态结构损坏按 corrupt 报错，而不是静默忽略）
	if needed, ok := r.dynamicNeeded(info, class); ok {
		info.SonameNeeded = needed
	}
	_ = name
	return info, nil
}

// shField 读取指定节头的 offset 与 size。
func (r *elfReader) shField(shoff int64, entsize, idx int, _, _ string) (int64, uint64) {
	base := shoff + int64(idx*entsize)
	if r.class == 2 {
		return int64(r.u64(base + 24)), r.u64(base + 32)
	}
	return int64(r.u32(base + 16)), uint64(r.u32(base + 20))
}

func (r *elfReader) u16(off int64) uint16 {
	if off+2 > int64(len(r.data)) {
		r.errOff = off
		return 0
	}
	return r.bo.Uint16(r.data[off:])
}
func (r *elfReader) u32(off int64) uint32 {
	if off+4 > int64(len(r.data)) {
		r.errOff = off
		return 0
	}
	return r.bo.Uint32(r.data[off:])
}
func (r *elfReader) u64(off int64) uint64 {
	if off+8 > int64(len(r.data)) {
		r.errOff = off
		return 0
	}
	return r.bo.Uint64(r.data[off:])
}

func (r *elfReader) slice(off int64, size uint64) ([]byte, error) {
	if off < 0 || size > uint64(len(r.data)) || uint64(off)+size > uint64(len(r.data)) {
		return nil, &ParseError{Kind: FailureTruncated, Format: FormatELF, Offset: off,
			Context: "data range outside file"}
	}
	return r.data[off : uint64(off)+size], nil
}

func elfString(tab []byte, idx uint32) (string, error) {
	if int(idx) >= len(tab) {
		return "", &ParseError{Kind: FailureCorrupt, Format: FormatELF, Offset: int64(idx),
			Context: "string index out of table"}
	}
	end := int(idx)
	for end < len(tab) && tab[end] != 0 {
		end++
	}
	return string(tab[idx:end]), nil
}

// dynamicNeeded 解析 PT_DYNAMIC 中的 DT_NEEDED。返回 (nil,false) 表示无动态段。
func (r *elfReader) dynamicNeeded(info *BinaryInfo, class byte) ([]string, bool) {
	var phoff int64
	var phentsize, phnum int
	if class == 2 {
		phoff = int64(r.u64(32))
		phentsize = int(r.u16(54))
		phnum = int(r.u16(56))
	} else {
		phoff = int64(r.u32(28))
		phentsize = int(r.u16(42))
		phnum = int(r.u16(44))
	}
	if phnum == 0 || phoff == 0 {
		return nil, false
	}
	want := 56
	if class == 1 {
		want = 32
	}
	if phentsize < want || uint64(phoff)+uint64(phnum)*uint64(phentsize) > uint64(len(r.data)) {
		return nil, false
	}
	var dynAddr, dynSize uint64
	for i := 0; i < phnum; i++ {
		b := phoff + int64(i*phentsize)
		ptype := r.u32(b)
		if ptype != 2 { // PT_DYNAMIC
			continue
		}
		if class == 2 {
			dynAddr = r.u64(b + 16)
			dynSize = r.u64(b + 32)
		} else {
			dynAddr = uint64(r.u32(b + 8))
			dynSize = uint64(r.u32(b + 16))
		}
		break
	}
	if dynAddr == 0 {
		return nil, false
	}
	dynOff := r.vaddrToOff(phoff, phentsize, phnum, class, dynAddr)
	if dynOff < 0 {
		return nil, false
	}
	entSize := uint64(16)
	if class == 1 {
		entSize = 8
	}
	var needed []uint64
	var strtabAddr uint64
	for off := dynOff; uint64(off-dynOff) < dynSize; off += int64(entSize) {
		var tag, val uint64
		if class == 2 {
			tag = r.u64(off)
			val = r.u64(off + 8)
		} else {
			tag = uint64(r.u32(off))
			val = uint64(r.u32(off + 4))
		}
		if tag == 0 { // DT_NULL
			break
		}
		switch tag {
		case 1: // DT_NEEDED
			needed = append(needed, val)
		case 5: // DT_STRTAB
			strtabAddr = val
		}
	}
	if strtabAddr == 0 || len(needed) == 0 {
		return nil, true
	}
	strOff := r.vaddrToOff(phoff, phentsize, phnum, class, strtabAddr)
	if strOff < 0 {
		return nil, true
	}
	out := make([]string, 0, len(needed))
	for _, idx := range needed {
		s, err := elfString(r.data[strOff:], uint32(idx))
		if err != nil {
			return nil, true
		}
		out = append(out, s)
	}
	return out, true
}

func (r *elfReader) vaddrToOff(phoff int64, phentsize, phnum int, class byte, vaddr uint64) int64 {
	for i := 0; i < phnum; i++ {
		b := phoff + int64(i*phentsize)
		if r.u32(b) != 1 { // PT_LOAD
			continue
		}
		var offset, vStart, fSize uint64
		if class == 2 {
			offset = r.u64(b + 8)
			vStart = r.u64(b + 16)
			fSize = r.u64(b + 32)
		} else {
			offset = uint64(r.u32(b + 4))
			vStart = uint64(r.u32(b + 8))
			fSize = uint64(r.u32(b + 16))
		}
		if vaddr >= vStart && vaddr < vStart+fSize {
			return int64(offset + (vaddr - vStart))
		}
	}
	return -1
}

func entropy(b []byte) float64 {
	if len(b) == 0 {
		return -1
	}
	var count [256]int
	for _, c := range b {
		count[c]++
	}
	var h float64
	n := float64(len(b))
	for _, c := range count {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

func elfTypeName(t uint16) string {
	switch t {
	case 1:
		return "relocatable"
	case 2:
		return "exec"
	case 3:
		return "dyn"
	case 4:
		return "core"
	default:
		return "unknown"
	}
}

func elfMachineName(m uint16) string {
	switch m {
	case 0x03:
		return "x86"
	case 0x3e:
		return "amd64"
	case 0x28:
		return "arm"
	case 0xb7:
		return "arm64"
	case 0xf3:
		return "riscv64"
	default:
		return "unknown"
	}
}
