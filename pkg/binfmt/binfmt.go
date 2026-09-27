package binfmt

// Arch 表示目标指令集架构的可读名称。
type Arch string

// BinaryInfo 是从样本中解析出的、供规则使用的结构化事实集合。
type BinaryInfo struct {
	Format       Format
	Arch         Arch
	Bits         int    // 32 或 64
	Endian       string // "little" / "big"
	Type         string // 目标类型，如 "exec" / "dll"
	Entry        uint64
	Sections     []Section
	Imports      map[string][]string // 导入模块/DLL -> 符号列表
	Exports      []string
	SonameNeeded []string // ELF DT_NEEDED
	RawSize      int64
}

// Section 描述一个二进制节/段。
type Section struct {
	Name      string
	Size      uint64
	Entropy   float64 // 0..8，-1 表示未计算
	Addr      uint64
	Offset    uint64
	RawData   []byte // 可能为 nil
	Flags     uint64
	IsUPXLike bool // 名称疑似加壳（如 UPX0/.upx）
}

// Parse 解析一个二进制样本。
// 返回的错误一定是 *ParseError：格式不支持、截断、损坏均显式返回，绝不静默返回空结果。
func Parse(data []byte, name string) (*BinaryInfo, error) {
	switch IdentifyFormat(data) {
	case FormatELF:
		return parseELF(data, name)
	case FormatPE:
		return parsePE(data, name)
	default:
		return nil, &ParseError{
			Kind:    FailureUnrecognized,
			Offset:  0,
			Context: "unknown magic: neither ELF (\\x7fELF) nor PE (MZ) — supported formats are ELF and PE",
		}
	}
}

// IdentifyFormat 仅通过魔数判断格式；无法识别时返回空字符串。
func IdentifyFormat(data []byte) Format {
	if len(data) >= 4 && data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F' {
		return FormatELF
	}
	if len(data) >= 2 && data[0] == 'M' && data[1] == 'Z' {
		return FormatPE
	}
	return ""
}
