// Package binaryfmt performs minimal, dependency-free structural parsing of
// local binary samples (currently ELF and PE) and reports distinguishable
// errors for truncated, corrupt and unsupported inputs.
package binaryfmt

import (
	"errors"
	"fmt"
)

// FailureReason categorises why a sample could not be parsed.
type FailureReason string

const (
	ReasonUnsupportedFormat FailureReason = "unsupported_format"
	ReasonTruncated         FailureReason = "truncated"
	ReasonCorrupt           FailureReason = "corrupt"
)

// ParseError carries a machine-readable reason together with locatable
// context (file and byte offset) so failures are never silent or ambiguous.
type ParseError struct {
	Reason FailureReason
	File   string
	Offset int64
	Detail string
}

func (e *ParseError) Error() string {
	loc := e.File
	if loc == "" {
		loc = "<sample>"
	}
	return fmt.Sprintf("binary parse error (%s) in %s at offset %d: %s",
		e.Reason, loc, e.Offset, e.Detail)
}

// AsParseError extracts a *ParseError from an error chain.
func AsParseError(err error) (*ParseError, bool) {
	var pe *ParseError
	if errors.As(err, &pe) {
		return pe, true
	}
	return nil, false
}

// Sentinel errors used by callers that want to match on a specific reason.
var (
	ErrUnsupportedFormat = errors.New("unsupported binary format")
	ErrTruncated         = errors.New("truncated binary")
	ErrCorrupt           = errors.New("corrupt binary structure")
)
