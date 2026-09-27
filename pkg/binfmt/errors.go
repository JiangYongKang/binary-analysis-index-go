package binfmt

import "fmt"

// Format 表示样本可被识别的二进制格式种类。
type Format string

const (
	FormatELF Format = "ELF"
	FormatPE  Format = "PE"
)

// FailureKind 对解析阶段的失败原因做可区分的分类。
type FailureKind string

const (
	// FailureTruncated 表示文件头部或结构体声称的范围超出了实际数据。
	FailureTruncated FailureKind = "truncated"
	// FailureCorrupt 表示魔数正确，但内部结构非法或自相矛盾。
	FailureCorrupt FailureKind = "corrupt"
	// FailureUnsupported 表示文件可识别，但使用了本库不支持的子格式。
	FailureUnsupported FailureKind = "unsupported"
	// FailureUnrecognized 表示文件不属于任何支持的二进制格式。
	FailureUnrecognized FailureKind = "unrecognized"
)

// ParseError 携带可定位上下文的解析错误。
// 解析器绝不静默跳过：无法识别、截断、损坏都必须返回该错误。
type ParseError struct {
	Kind    FailureKind
	Format  Format // 已识别出的格式；尚未识别时为空
	Offset  int64  // 出错位置（字节偏移），未知时为 -1
	Context string // 人类可读的定位上下文
	Err     error  // 被包装的底层错误，可为 nil
}

func (e *ParseError) Error() string {
	loc := "offset=?"
	if e.Offset >= 0 {
		loc = fmt.Sprintf("offset=%d", e.Offset)
	}
	s := fmt.Sprintf("parse %s: %s: %s (%s)", e.Format, e.Kind, e.Context, loc)
	if e.Err != nil {
		s += ": " + e.Err.Error()
	}
	return s
}

func (e *ParseError) Unwrap() error { return e.Err }

// IsKind 判断 err 是否为 *ParseError 且分类为 kind。
// 这是调用方区分“无法解析 / 截断 / 不支持 / 损坏”的入口。
func IsKind(err error, kind FailureKind) bool {
	pe, ok := err.(*ParseError)
	return ok && pe.Kind == kind
}
