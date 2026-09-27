// Package rules defines the versioned detection-rule model used during
// analysis. Rule sets are immutable and identified by a version tag so that
// old results stay reproducible while newer results are clearly labelled.
package rules

import "context"

// Severity of a rule match.
type Severity string

const (
	SeverityInfo    Severity = "info"
	SeverityWarning Severity = "warning"
)

// Facts is the parsed view of a sample made available to rules.
type Facts struct {
	Format    string
	Class     string
	Machine   string
	Subsystem string
	Stripped  bool
	Sections  []Section
}

// Section mirrors binaryfmt.Section without importing that package, so the
// rules package stays independent of the parser implementation.
type Section struct {
	Name   string
	Size   uint64
	Offset uint64
}

// Match is one rule hit.
type Match struct {
	RuleID   string
	Severity Severity
	Message  string
}

// Rule evaluates one predicate over parsed facts. Evaluate returns a match
// (possibly nil) and an error; a rule error must abort the analysis rather
// than be silently skipped.
type Rule interface {
	ID() string
	Evaluate(ctx context.Context, facts Facts) (*Match, error)
}

// Set is an immutable, ordered collection of rules carrying a version tag.
type Set struct {
	version string
	rules   []Rule
}

// NewSet builds a rule set from an ordered list of rules. The rules slice is
// copied so callers cannot mutate a registered set afterwards.
func NewSet(version string, rs ...Rule) *Set {
	cp := make([]Rule, len(rs))
	copy(cp, rs)
	return &Set{version: version, rules: cp}
}

// Version returns the rule-set version tag.
func (s *Set) Version() string { return s.version }

// Rules returns the ordered rules of the set. The returned slice must not be
// mutated; conceptually a rule set is immutable.
func (s *Set) Rules() []Rule { return s.rules }

// HasSection reports whether the facts contain a section name.
func (f Facts) HasSection(name string) bool {
	for _, s := range f.Sections {
		if s.Name == name {
			return true
		}
	}
	return false
}
