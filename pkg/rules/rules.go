// Package rules 提供版本化的二进制分析规则集。
// 每个规则版本是不可变的：发布后不再修改，升级另立版本号，
// 从而保证旧分析结论可以用旧规则版本复现。
package rules

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/highcumontoa/binary-analysis-index-go/pkg/binfmt"
)

// Severity 表示规则命中的严重程度。
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Verdict 是对一个样本的最终判定。
type Verdict string

const (
	// VerdictClean 未命中任何规则。
	VerdictClean Verdict = "clean"
	// VerdictSuspicious 至少命中一条规则。
	VerdictSuspicious Verdict = "suspicious"
)

// Match 表示单条规则的一次命中。
type Match struct {
	RuleID   string
	Severity Severity
	Message  string
	Basis    string // 判定依据的可读描述
}

// Rule 是一条不可变的分析规则。
type Rule interface {
	ID() string
	Severity() Severity
	// Eval 检查样本；ok=true 表示命中。
	// 规则自身无法完成检查时必须返回 error，由引擎包装为“规则执行失败”，
	// 不允许吞掉错误后返回“未命中”。
	Eval(ctx context.Context, info *binfmt.BinaryInfo) (ok bool, msg string, basis string, err error)
}

// RuleError 表示某条规则执行失败，携带规则 ID 与上下文，可与解析错误区分。
type RuleError struct {
	RuleID  string
	Version string
	Err     error
}

func (e *RuleError) Error() string {
	return fmt.Sprintf("rule %q (version %s) execution failed: %v", e.RuleID, e.Version, e.Err)
}

func (e *RuleError) Unwrap() error { return e.Err }

// Engine 是某个固定规则版本的执行器。Engine 对并发使用安全。
type Engine struct {
	version string
	rules   []Rule
}

// NewEngine 构造一个不可变规则引擎。
func NewEngine(version string, rs []Rule) *Engine {
	cp := make([]Rule, len(rs))
	copy(cp, rs)
	return &Engine{version: version, rules: cp}
}

// Version 返回引擎的规则版本标识。
func (e *Engine) Version() string { return e.version }

// Rules 返回引擎内规则 ID 的快照副本（按字典序，便于日志与断言）。
func (e *Engine) Rules() []string {
	ids := make([]string, len(e.rules))
	for i, r := range e.rules {
		ids[i] = r.ID()
	}
	sort.Strings(ids)
	return ids
}

// Analyze 用该版本的全部规则分析样本，返回命中列表与最终判定。
// 任一条规则执行失败都会立即返回 *RuleError；调用方不应把这种情况当作 clean。
// 规则按注册顺序执行；ctx 取消时正在执行的规则会感知到取消。
func (e *Engine) Analyze(ctx context.Context, info *binfmt.BinaryInfo) (matches []Match, verdict Verdict, basis string, err error) {
	if info == nil {
		return nil, "", "", &RuleError{Version: e.version, Err: fmt.Errorf("nil BinaryInfo")}
	}
	for _, r := range e.rules {
		if err := ctx.Err(); err != nil {
			return nil, "", "", &RuleError{RuleID: r.ID(), Version: e.version, Err: err}
		}
		ok, msg, why, rerr := r.Eval(ctx, info)
		if rerr != nil {
			return nil, "", "", &RuleError{RuleID: r.ID(), Version: e.version, Err: rerr}
		}
		if ok {
			matches = append(matches, Match{
				RuleID:   r.ID(),
				Severity: r.Severity(),
				Message:  msg,
				Basis:    why,
			})
		}
	}
	if len(matches) == 0 {
		return matches, VerdictClean,
			fmt.Sprintf("no rule matched in version %s across %d rules", e.version, len(e.rules)), nil
	}
	ids := make([]string, len(matches))
	for i, m := range matches {
		ids[i] = m.RuleID
	}
	return matches, VerdictSuspicious,
		fmt.Sprintf("matched %d rule(s) in version %s: %s", len(matches), e.version, strings.Join(ids, ",")), nil
}
