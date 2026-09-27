// Package scan glues content hashing, the analysis engine and the index
// together: callers name a file and a rule-set version; scan hashes the
// content once, reuses any existing record for that (hash, version), and
// otherwise runs the analyzer.
package scan

import (
	"context"
	"fmt"
	"os"

	"github.com/highcumontoa/binary-analysis-index-go/internal/analysis"
	"github.com/highcumontoa/binary-analysis-index-go/internal/index"
)

// Service combines an analyzer and an index.
type Service struct {
	analyzer *analysis.Analyzer
	idx      *index.Index
}

// New constructs a Service.
func New(analyzer *analysis.Analyzer, idx *index.Index) *Service {
	return &Service{analyzer: analyzer, idx: idx}
}

// Index exposes the underlying index for queries.
func (s *Service) Index() *index.Index { return s.idx }

// SampleID computes the SHA-256 content hash (hex) of a file.
func SampleID(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", 0, err
	}
	id, err := analysis.HashContent(f, st.Size())
	if err != nil {
		return "", 0, err
	}
	return id, st.Size(), nil
}

// AnalyzerFunc adapts the concrete analyzer to the index's function type.
// It re-opens the file by path (the shared, detached analysis must not hold
// any single caller's open file descriptor).
func (s *Service) AnalyzerFunc() index.AnalyzerFunc {
	return func(ctx context.Context, file, sampleID, ruleVersion string) (*analysis.Result, error) {
		f, err := os.Open(file)
		if err != nil {
			return nil, fmt.Errorf("open sample %q: %w", file, err)
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil {
			return nil, fmt.Errorf("stat sample %q: %w", file, err)
		}
		res, err := s.analyzer.Analyze(ctx, file, f, st.Size(), ruleVersion)
		if err != nil {
			return nil, err
		}
		res.SampleID = sampleID
		return res, nil
	}
}

// ScanFile hashes path and ensures it is indexed under ruleVersion.
func (s *Service) ScanFile(ctx context.Context, path, ruleVersion string) (*index.Record, error) {
	id, _, err := SampleID(path)
	if err != nil {
		return nil, err
	}
	return s.idx.Scan(ctx, path, id, ruleVersion)
}
