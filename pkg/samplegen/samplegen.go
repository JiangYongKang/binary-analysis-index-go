// Package samplegen 在测试中生成最小化但结构合法的 ELF/PE 样本，
// 以及可控的截断/损坏变体，不依赖任何外部工具、在线服务或真实样本。
package samplegen

import (
	"bytes"
	"encoding/binary"
	"math/rand"
)

// Spec 描述要生成的样本。
type Spec struct {
	// Sections 为节名列表；名为 ".upx" / "UPX0" 的节填高熵数据，其余节填低熵代码样数据。
	Sections []string
	// Imports 为 DLL -> 导入符号（仅 PE 使用）。
	Imports map[string][]string
	// Needed 为 ELF DT_NEEDED 条目（可选；生成带 PT_DYNAMIC 的 ELF）。
	Needed []string
	// TruncateAt > 0 时，在该字节偏移处截断输出（模拟文件被截断）。
	TruncateAt int
	// Corrupt 注入内部损坏：
	//   ELF: "class"(不支持的 EI_CLASS) / "section-offset"(节数据越界)
	//   PE : "coff-signature"(PE 签名损坏) / "section-offset"(节原始数据越界) / "rva"(导入名 RVA 非法)
	Corrupt string
	// DLL 为 true 时生成 PE DLL（IMAGE_FILE_DLL）。
	DLL bool
}

// RandomBytes 返回确定性的高熵伪随机数据（固定种子，跨进程可复现）。
func RandomBytes(n int) []byte {
	rng := rand.New(rand.NewSource(1))
	b := make([]byte, n)
	rng.Read(b)
	return b
}

// ELF64 生成一个最小合法 64 位小端 ET_EXEC ELF：
// 含 ELF 头、节头表、.shstrtab 以及 Spec 指定的节数据。
func ELF64(spec Spec) ([]byte, error) {
	bo := binary.LittleEndian
	const ehsize, shentsize = 64, 64
	// 节列表：null + 用户节 + .shstrtab
	user := spec.Sections
	shnum := 1 + len(user) + 1
	shstrndx := uint16(shnum - 1)

	// 字符串表
	var strtab bytes.Buffer
	strtab.WriteByte(0) // 索引 0 为空串
	nameOff := make(map[string]uint32)
	for _, n := range user {
		nameOff[n] = uint32(strtab.Len())
		strtab.WriteString(n)
		strtab.WriteByte(0)
	}
	strNameOff := uint32(strtab.Len())
	strtab.WriteString(".shstrtab")
	strtab.WriteByte(0)

	// 文件布局：ELF 头 | 节头表 | 各节数据（含 .shstrtab）
	dataStart := int64(ehsize + shnum*shentsize)
	// 计算每节文件偏移与数据
	type secBlob struct {
		name string
		data []byte
	}
	blobs := make([]secBlob, 0, len(user))
	off := dataStart
	type secLoc struct {
		offset, size uint64
	}
	locs := make(map[string]secLoc)
	for _, n := range user {
		var payload []byte
		if isUPXSectionName(n) {
			payload = RandomBytes(1024)
		} else {
			payload = bytes.Repeat([]byte{0x90, 0x00, 0x48, 0x31}, 16) // 64 字节低熵
		}
		locs[n] = secLoc{uint64(off), uint64(len(payload))}
		blobs = append(blobs, secBlob{n, payload})
		off += int64(len(payload))
	}
	strLoc := secLoc{uint64(off), uint64(strtab.Len())}
	totalSize := off + int64(strtab.Len())

	buf := make([]byte, totalSize)
	// e_ident
	buf[0], buf[1], buf[2], buf[3] = 0x7f, 'E', 'L', 'F'
	buf[4] = 2                             // ELFCLASS64
	buf[5] = 1                             // ELFDATA2LSB
	buf[6] = 1                             // EV_CURRENT
	bo.PutUint16(buf[16:], 2)              // e_type ET_EXEC
	bo.PutUint16(buf[18:], 0x3e)           // e_machine x86-64
	bo.PutUint32(buf[20:], 1)              // e_version
	bo.PutUint64(buf[24:], 0x400000)       // e_entry
	bo.PutUint64(buf[32:], 0)              // e_phoff
	bo.PutUint64(buf[40:], uint64(ehsize)) // e_shoff
	bo.PutUint16(buf[52:], 64)             // e_ehsize
	bo.PutUint16(buf[58:], shentsize)      // e_shentsize
	bo.PutUint16(buf[60:], uint16(shnum))  // e_shnum
	bo.PutUint16(buf[62:], shstrndx)       // e_shstrndx

	sh := ehsize
	putSh := func(idx int, name uint32, typ, flags uint32, offset, size uint64) {
		b := sh + idx*shentsize
		bo.PutUint32(buf[b+0:], name)
		bo.PutUint32(buf[b+4:], typ)
		bo.PutUint64(buf[b+8:], uint64(flags))
		bo.PutUint64(buf[b+24:], offset)
		bo.PutUint64(buf[b+32:], size)
	}
	// idx=0 全零（null 节头）
	for i, n := range user {
		l := locs[n]
		flags := uint32(0x2 | 0x4) // ALLOC | EXECINSTR
		typ := uint32(1)           // SHT_PROGBITS
		if isUPXSectionName(n) {
			flags = 0x1 | 0x2 // WRITE|ALLOC，模拟加壳节
		}
		putSh(1+i, nameOff[n], typ, flags, l.offset, l.size)
	}
	putSh(int(shstrndx), strNameOff, 3, 0, strLoc.offset, strLoc.size) // SHT_STRTAB

	for _, bl := range blobs {
		l := locs[bl.name]
		copy(buf[l.offset:], bl.data)
	}
	copy(buf[strLoc.offset:], strtab.Bytes())

	if spec.Corrupt == "class" {
		buf[4] = 9 // 非法 EI_CLASS → unsupported
	}
	if spec.Corrupt == "section-offset" && len(user) > 0 {
		b := sh + 1*shentsize
		bo.PutUint64(buf[b+24:], uint64(totalSize)+100) // 节偏移越界 → truncated
	}
	if spec.Corrupt == "shstrndx" {
		bo.PutUint16(buf[62:], uint16(shnum+10)) // e_shstrndx 越界 → corrupt
	}
	if spec.TruncateAt > 0 && spec.TruncateAt < len(buf) {
		buf = buf[:spec.TruncateAt]
	}
	return buf, nil
}

func isUPXSectionName(n string) bool {
	for i := 0; i+3 <= len(n); i++ {
		c0, c1, c2 := n[i], n[i+1], n[i+2]
		if c0 >= 'a' && c0 <= 'z' {
			c0 -= 32
		}
		if c1 >= 'a' && c1 <= 'z' {
			c1 -= 32
		}
		if c2 >= 'a' && c2 <= 'z' {
			c2 -= 32
		}
		if c0 == 'U' && c1 == 'P' && c2 == 'X' {
			return true
		}
	}
	return n == ".upx"
}

var _ = bytes.Repeat

// PE32Plus 生成一个最小合法 64 位 PE（PE32+）：
// MZ 头 + COFF/可选头 + 节表 + 节数据（含可解析的导入目录）。
func PE32Plus(spec Spec) ([]byte, error) {
	bo := binary.LittleEndian
	const (
		dosSize   = 64
		coffSize  = 20
		optSize   = 240 // PE32+ 固定可选头（含 16 项数据目录）
		hdrEnd    = dosSize + 4 + coffSize + optSize
		sectEntry = 40
		fileAlign = 0x200
		sectAlign = 0x1000
		imageBase = 0x140000000
	)

	// 组装 .rdata 内容（导入结构），记录各部分 RVA（稍后用虚拟基址回填）。
	var rdata []byte
	pad8 := func() {
		for len(rdata)%8 != 0 {
			rdata = append(rdata, 0)
		}
	}
	// 稳定顺序：Go map 遍历无序，先排序保证输出确定性
	names := make([]string, 0, len(spec.Imports))
	for k := range spec.Imports {
		names = append(names, k)
	}
	for i := 1; i < len(names); i++ { // 简单插入排序
		for j := i; j > 0 && names[j-1] > names[j]; j-- {
			names[j-1], names[j] = names[j], names[j-1]
		}
	}
	iltSize := func(n int) int { return (n + 1) * 8 }
	type dllPlan struct {
		dll     string
		funcs   []string
		iltOff  int
		iatOff  int
		nameOff int
		hnOffs  []int
		descOff int
	}
	plans := make([]*dllPlan, 0, len(names))
	for _, dll := range names {
		plans = append(plans, &dllPlan{dll: dll, funcs: spec.Imports[dll]})
	}
	// 布局（.rdata 内偏移）：先放描述符数组（末尾紧跟全零结束项），
	// 再放每个 DLL 的 ILT、IAT、hint/name、dllname。
	for _, p := range plans {
		p.descOff = len(rdata)
		rdata = append(rdata, make([]byte, 20)...)
	}
	rdata = append(rdata, make([]byte, 20)...) // 全零结束项
	for _, p := range plans {
		pad8()
		p.iltOff = len(rdata)
		rdata = append(rdata, make([]byte, iltSize(len(p.funcs)))...)
		pad8()
		p.iatOff = len(rdata)
		rdata = append(rdata, make([]byte, iltSize(len(p.funcs)))...)
		for _, f := range p.funcs {
			if len(rdata)%2 != 0 {
				rdata = append(rdata, 0)
			}
			p.hnOffs = append(p.hnOffs, len(rdata))
			rdata = append(rdata, 0, 0) // hint
			rdata = append(rdata, []byte(f)...)
			rdata = append(rdata, 0)
		}
		if len(rdata)%2 != 0 {
			rdata = append(rdata, 0)
		}
		p.nameOff = len(rdata)
		rdata = append(rdata, []byte(p.dll)...)
		rdata = append(rdata, 0)
	}
	if len(rdata)%fileAlign != 0 {
		rdata = append(rdata, make([]byte, fileAlign-len(rdata)%fileAlign)...)
	}
	rdataBytes := rdata

	// 节：.text + .rdata（始终存在，保证导入目录位置稳定）
	type secDef struct {
		name string
		body []byte
	}
	textBody := bytes.Repeat([]byte{0x90, 0x31, 0xc0, 0xc3}, 16) // 64 字节
	defs := []secDef{{".text", textBody}, {".rdata", rdataBytes}}
	for _, n := range spec.Sections {
		var payload []byte
		if isUPXSectionName(n) {
			payload = RandomBytes(1024)
		} else {
			payload = bytes.Repeat([]byte{0xcc, 0x00}, 32)
		}
		defs = append(defs, secDef{n, payload})
	}
	numSec := len(defs)
	sectTableOff := hdrEnd
	sectDataOff := align(sectTableOff+numSec*sectEntry, fileAlign)

	// 计算各节文件偏移与 RVA
	type secMap struct {
		vaddr, rawOff uint32
		vsize, rawSz  uint32
	}
	maps := make([]secMap, numSec)
	foff := sectDataOff
	vaddr := uint32(sectAlign)
	for i, d := range defs {
		raw := align(len(d.body), fileAlign)
		maps[i] = secMap{vaddr, uint32(foff), uint32(len(d.body)), uint32(raw)}
		foff += raw
		vaddr += uint32(align(len(d.body), sectAlign))
	}
	fileSize := foff
	buf := make([]byte, fileSize)

	// DOS 头
	buf[0], buf[1] = 'M', 'Z'
	bo.PutUint32(buf[0x3c:], dosSize)
	// PE 签名
	copy(buf[dosSize:], "PE\x00\x00")
	coff := dosSize + 4
	bo.PutUint16(buf[coff+0:], 0x8664) // AMD64
	bo.PutUint16(buf[coff+2:], uint16(numSec))
	bo.PutUint32(buf[coff+4:], 0) // TimeDateStamp
	bo.PutUint16(buf[coff+16:], optSize)
	chars := uint16(0x0002) // IMAGE_FILE_EXECUTABLE_IMAGE
	if spec.DLL {
		chars |= 0x2000
	}
	bo.PutUint16(buf[coff+18:], chars)
	// 可选头 PE32+
	opt := coff + coffSize
	bo.PutUint16(buf[opt+0:], 0x20b)
	buf[opt+2] = 14                           // MajorLinkerVersion
	bo.PutUint32(buf[opt+4:], 0)              // SizeOfCode（简化）
	bo.PutUint32(buf[opt+16:], maps[0].vaddr) // AddressOfEntryPoint -> .text
	bo.PutUint64(buf[opt+24:], imageBase)
	bo.PutUint32(buf[opt+32:], sectAlign) // SectionAlignment
	bo.PutUint32(buf[opt+36:], fileAlign) // FileAlignment
	bo.PutUint16(buf[opt+40:], 6)         // MajorOperatingSystemVersion
	bo.PutUint16(buf[opt+42:], 0)
	bo.PutUint16(buf[opt+44:], 0) // MajorImageVersion
	bo.PutUint16(buf[opt+46:], 0)
	bo.PutUint16(buf[opt+48:], 6) // MajorSubsystemVersion
	bo.PutUint16(buf[opt+50:], 0)
	bo.PutUint32(buf[opt+52:], 0)                   // Win32VersionValue
	bo.PutUint32(buf[opt+56:], vaddr)               // SizeOfImage
	bo.PutUint32(buf[opt+60:], uint32(sectDataOff)) // SizeOfHeaders
	bo.PutUint32(buf[opt+64:], 0)                   // CheckSum
	bo.PutUint16(buf[opt+68:], 3)                   // Subsystem: CONSOLE
	bo.PutUint16(buf[opt+70:], 0x8160)              // DllCharacteristics
	bo.PutUint64(buf[opt+72:], 0x100000)            // SizeOfStackReserve
	bo.PutUint64(buf[opt+80:], 0x1000)              // SizeOfStackCommit
	bo.PutUint64(buf[opt+88:], 0x100000)            // SizeOfHeapReserve
	bo.PutUint64(buf[opt+96:], 0x1000)              // SizeOfHeapCommit
	bo.PutUint32(buf[opt+104:], 0)                  // LoaderFlags
	bo.PutUint32(buf[opt+108:], 16)                 // NumberOfRvaAndSizes

	// .rdata 的 RVA 基址（maps 已先计算，但节数据拷贝必须在导入结构回填之后）
	rdataIdx := 1
	rva := func(rdataOff int) uint32 {
		return maps[rdataIdx].vaddr + uint32(rdataOff)
	}
	// 回填导入结构（直接改写最终要拷进镜像的 rdataBytes）
	w64 := func(off int, v uint64) { bo.PutUint64(rdataBytes[off:], v) }
	w32 := func(off int, v uint32) { bo.PutUint32(rdataBytes[off:], v) }
	for _, p := range plans {
		for i, hn := range p.hnOffs {
			w64(p.iltOff+i*8, uint64(rva(hn)))
			w64(p.iatOff+i*8, uint64(rva(hn)))
		}
		w32(p.descOff+0, rva(p.iltOff)) // OriginalFirstThunk
		w32(p.descOff+12, rva(p.nameOff))
		w32(p.descOff+16, rva(p.iatOff))
	}
	importDirRVA := rva(0) // 描述符数组位于 .rdata 起始
	if len(plans) > 0 {
		importDirSize := uint32((len(plans) + 1) * 20)
		// 数据目录[1] = Import Table：PE32+ 数据目录起点 opt+112，导入表偏移 +8
		ddImport := opt + 112 + 8
		bo.PutUint32(buf[ddImport:], importDirRVA)
		bo.PutUint32(buf[ddImport+4:], importDirSize)
	}

	// 节表与节数据（在导入结构回填之后拷贝）
	for i, d := range defs {
		b := sectTableOff + i*sectEntry
		copy(buf[b:b+8], d.name)
		bo.PutUint32(buf[b+8:], maps[i].vsize)
		bo.PutUint32(buf[b+12:], maps[i].vaddr)
		bo.PutUint32(buf[b+16:], maps[i].rawSz)
		bo.PutUint32(buf[b+20:], maps[i].rawOff)
		ch := uint32(0x40000040) // READ|EXEC
		if d.name == ".rdata" {
			ch = 0x40000040 // READ（初始化数据位按可读处理，简化）
		}
		if isUPXSectionName(d.name) {
			ch = 0xC0000040 | 0x80000000 // READ|WRITE|EXEC
		}
		bo.PutUint32(buf[b+36:], ch)
		copy(buf[maps[i].rawOff:], d.body)
	}

	if spec.Corrupt == "coff-signature" {
		copy(buf[dosSize:], "XX\x00\x00")
	}
	if spec.Corrupt == "section-offset" {
		b := sectTableOff
		bo.PutUint32(buf[b+20:], uint32(fileSize)+512) // 第一节 raw offset 越界
	}
	if spec.Corrupt == "rva" && len(plans) > 0 {
		ddImport := opt + 112 + 8
		bo.PutUint32(buf[ddImport:], 0x7ffff000) // 非法 RVA
	}
	if spec.TruncateAt > 0 && spec.TruncateAt < len(buf) {
		buf = buf[:spec.TruncateAt]
	}
	return buf, nil
}

func align(v, a int) int { return (v + a - 1) / a * a }
