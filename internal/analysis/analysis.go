// Package analysis orchestrates parsing a single sample and evaluating a
// versioned rule set, producing a reproducible verdict. Results are
// content-addressed by a SHA-256 hash combined with the rule-set version,
// which makes incremental analysis safe: identical bytes with the same rule
// version always yield the same result.
package analysis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/highcumontoa/binary-analysis-index-go/internal/binaryfmt"
	"github.com/highcumontoa/binary-analysis-index-go/internal/rules"
)

// Verdict is the final decision for a sample.
type Verdict string

const (
	// Clean means the sample parsed and no warning rule matched.
	Clean Verdict = "clean"
	// Suspicious means at least one warning-severity rule matched.
	Suspicious Verdict = "suspicious"
)

// FailureKind categorises an analysis failure. The categories map 1:1 to the
// distinguishable error conditions callers must react to.
type FailureKind string

const (
	FailureUnsupportedFormat FailureKind = "unsupported_format"
	FailureTruncated         FailureKind = "truncated"
	FailureCorrupt           FailureKind = "corrupt"
	FailureRuleExecution     FailureKind = "rule_execution"
)

// Failure keeps a distinguishable error plus locatable context.
type Failure struct {
	Kind    FailureKind
	File    string
	Offset  int64
	RuleID  string
	Message string
}

func (f *Failure) Error() string {
	switch f.Kind {
	case FailureRuleExecution:
		return fmt.Sprintf("analysis failure (%s) in %s: rule %q: %s",
			f.Kind, f.File, f.RuleID, f.Message)
	default:
		return fmt.Sprintf("analysis failure (%s) in %s at offset %d: %s",
			f.Kind, f.File, f.Offset, f.Message)
	}
}

// Match is one rule hit recorded on a result.
type Match struct {
	RuleID   string
	Severity string
	Message  string
}

// Result is the structured outcome of analysing one sample under one rule
// set. It is immutable after creation and safe to share.
type Result struct {
	SampleID string // SHA-256 of file content, hex encoded
	Filename string
	Size     int64
	Format   string
	Class    string
	Machine  string
	Version  string // rule-set version used
	Verdict  Verdict
	Matches  []Match
	// Basis is the human-readable explanation of why the verdict was chosen.
	Basis string
	// Failed is nil on success; otherwise the distinguishable failure.
	Failed *Failure
}

// IsFailure reports whether analysis failed.
func (r *Result) IsFailure() bool { return r.Failed != nil }

// Analyzer parses samples and evaluates rule sets.
type Analyzer struct {
	registry *rules.Registry
}

// NewAnalyzer creates an Analyzer backed by the given rule registry.
func NewAnalyzer(reg *rules.Registry) *Analyzer { return &Analyzer{registry: reg} }

// Analyze parses r (size bytes, named file) and evaluates the rule set
// identified by ruleVersion. Parse and rule failures are returned inside a
// *Result with Failed set (never silently skipped), while the error return is
// reserved for infrastructure problems: unknown rule version, or context
// cancellation/timeout, which produce no result at all.
func (a *Analyzer) Analyze(ctx context.Context, file string, r io.ReaderAt, size int64, ruleVersion string) (*Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	set, err := a.registry.Get(ruleVersion)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", errRuleSetMissing, ruleVersion)
	}

	info, perr := binaryfmt.Parse(file, r, size)
	if perr != nil {
		return &Result{
			Filename: file,
			Size:     size,
			Version:  ruleVersion,
			Verdict:  "",
			Failed:   mapFailure(file, perr),
		}, nil
	}

	facts := rules.Facts{
		Format:    string(info.Format),
		Class:     string(info.Class),
		Machine:   info.Machine,
		Subsystem: info.Subsystem,
		Stripped:  info.Stripped,
	}
	for _, s := range info.Sections {
		facts.Sections = append(facts.Sections, rules.Section{Name: s.Name, Size: s.Size, Offset: s.Offset})
	}

	var matches []Match
	var warnings []string
	var infos []string
	for _, rule := range set.Rules() {
		// Cooperative cancellation: an aborted request must not finish a
		// rule evaluation and must not leave a partial verdict behind.
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		m, rerr := rule.Evaluate(ctx, facts)
		if rerr != nil {
			return &Result{
				Filename: file,
				Size:     size,
				Format:   string(info.Format),
				Class:    string(info.Class),
				Machine:  info.Machine,
				Version:  ruleVersion,
				Failed: &Failure{
					Kind:    FailureRuleExecution,
					File:    file,
					RuleID:  rule.ID(),
					Message: rerr.Error(),
				},
			}, nil
		}
		if m == nil {
			continue
		}
		matches = append(matches, Match{RuleID: m.RuleID, Severity: string(m.Severity), Message: m.Message})
		if m.Severity == rules.SeverityWarning {
			warnings = append(warnings, m.RuleID)
		} else {
			infos = append(infos, m.RuleID)
		}
	}

	res := &Result{
		Filename: file,
		Size:     size,
		Format:   string(info.Format),
		Class:    string(info.Class),
		Machine:  info.Machine,
		Version:  ruleVersion,
		Matches:  matches,
	}
	if len(warnings) > 0 {
		res.Verdict = Suspicious
		res.Basis = fmt.Sprintf("warning rules matched: %s", strings.Join(warnings, ", "))
	} else {
		res.Verdict = Clean
		if len(infos) > 0 {
			res.Basis = fmt.Sprintf("no warning rules matched; info matches: %s", strings.Join(infos, ", "))
		} else {
			res.Basis = "no rules matched"
		}
	}
	return res, nil
}

// HashContent returns the SHA-256 (hex) of r's full contents.
func HashContent(r io.Reader, size int64) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// mapFailure converts a parser error into an analysis Failure.
func mapFailure(file string, err error) *Failure {
	if pe, ok := binaryfmt.AsParseError(err); ok {
		return &Failure{
			Kind:    parseFailureKind(pe.Reason),
			File:    file,
			Offset:  pe.Offset,
			Message: pe.Detail,
		}
	}
	return &Failure{Kind: FailureCorrupt, File: file, Message: err.Error()}
}

// parseFailureKind maps binaryfmt failure reasons onto analysis kinds.
func parseFailureKind(reason binaryfmt.FailureReason) FailureKind {
	switch reason {
	case binaryfmt.ReasonUnsupportedFormat:
		return FailureUnsupportedFormat
	case binaryfmt.ReasonTruncated:
		return FailureTruncated
	case binaryfmt.ReasonCorrupt:
		return FailureCorrupt
	default:
		return FailureCorrupt
	}
}

// errRuleSetMissing wraps infrastructure errors returned beside a Result.
var errRuleSetMissing = errors.New("rule set version not found")
