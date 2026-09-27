// Package index 实现本地二进制样本分析索引：
// 内容寻址、增量分析、并发去重、规则版本共存与快照式一致性更新。
package index

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/highcumontoa/binary-analysis-index-go/pkg/binfmt"
	"github.com/highcumontoa/binary-analysis-index-go/pkg/rules"
)

// Status 表示一条分析记录的状态。
type Status string

const (
	// StatusOK 分析成功完成（可能是 clean 或 suspicious）。
	StatusOK Status = "ok"
	// StatusFailed 解析或规则执行失败。失败也是一种显式结论，原因可区分。
	StatusFailed Status = "failed"
)

// Failure 描述失败分析的可区分原因与定位上下文。
type Failure struct {
	// Kind 为解析类原因（truncated/corrupt/unsupported/unrecognized），
	// 或 "rule_failed"（规则执行失败）、"internal"（其它内部错误）。
	Kind     string        `json:"kind"`
	RuleID   string        `json:"rule_id,omitempty"`
	Format   binfmt.Format `json:"format,omitempty"`
	Offset   int64         `json:"offset"`
	Context  string        `json:"context,omitempty"`
	Embedded string        `json:"embedded,omitempty"`
}

// Record 是某个内容哈希在某个规则版本下的一条不可变分析结论。
type Record struct {
	ContentID   string        `json:"content_id"`  // SHA-256 内容哈希（十六进制）
	SampleName  string        `json:"sample_name"` // 仅展示用，不参与去重
	Size        int64         `json:"size"`
	RuleVersion string        `json:"rule_version"`
	Status      Status        `json:"status"`
	Verdict     rules.Verdict `json:"verdict,omitempty"`
	Matches     []rules.Match `json:"matches,omitempty"`
	Basis       string        `json:"basis,omitempty"`
	Failure     *Failure      `json:"failure,omitempty"`
	AnalyzedAt  time.Time     `json:"analyzed_at"`
}

// Key 生成版本化存储键。同一内容在不同规则版本下是不同记录，可共存。
func (r *Record) Key() string {
	return RecordKey(r.ContentID, r.RuleVersion)
}

// RecordKey 是内容标识 + 规则版本的复合键。
func RecordKey(contentID, ruleVersion string) string {
	return contentID + "@" + ruleVersion
}

// ContentID 返回数据的 SHA-256 内容标识。相同字节内容永远得到相同标识，
// 因此“已成功分析过的同一文件内容”可被精确识别，绝不重复分析。
func ContentID(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
