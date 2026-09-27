package index_test

import (
	"context"
	"os"
	"sync/atomic"
	"testing"

	"github.com/highcumontoa/binary-analysis-index-go/internal/analysis"
	"github.com/highcumontoa/binary-analysis-index-go/internal/index"
	"github.com/highcumontoa/binary-analysis-index-go/internal/rules"
	"github.com/highcumontoa/binary-analysis-index-go/internal/samples"
)

// testEnv bundles a generated sample set with a registry containing the
// built-in v1/v2 rule sets.
type testEnv struct {
	set *samples.Set
	reg *rules.Registry
}

func newEnv(t *testing.T) *testEnv {
	t.Helper()
	set, err := samples.Create(t.TempDir())
	if err != nil {
		t.Fatalf("create samples: %v", err)
	}
	reg := rules.NewRegistry()
	reg.MustRegister(rules.BuiltinV1())
	reg.MustRegister(rules.BuiltinV2())
	return &testEnv{set: set, reg: reg}
}

// countingAnalyzer returns an AnalyzerFunc that counts how many times the
// underlying analysis actually ran, keyed by record key.
func countingAnalyzer(reg *rules.Registry) (index.AnalyzerFunc, *atomic.Int64) {
	var calls atomic.Int64
	az := analysis.NewAnalyzer(reg)
	fn := func(ctx context.Context, file, sampleID, version string) (*analysis.Result, error) {
		calls.Add(1)
		f, err := os.Open(file)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil {
			return nil, err
		}
		res, err := az.Analyze(ctx, file, f, st.Size(), version)
		if err != nil {
			return nil, err
		}
		res.SampleID = sampleID
		return res, nil
	}
	return fn, &calls
}

func mustHash(t *testing.T, path string) (string, int64) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	id, err := analysis.HashContent(f, st.Size())
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	return id, st.Size()
}

func logRecord(t *testing.T, r *index.Record) {
	t.Helper()
	if r.Status == index.StatusFailed {
		t.Logf("sample=%s file=%s rules=%s FINAL=status:failed reason=%s offset=%d rule=%s detail=%q",
			short(r.SampleID), r.Filename, r.Version, r.Error.Kind, r.Error.Offset, r.Error.RuleID, r.Error.Message)
		return
	}
	var hits []string
	for _, m := range r.Matches {
		hits = append(hits, m.RuleID+":"+m.Severity)
	}
	t.Logf("sample=%s file=%s rules=%s hits=%v FINAL=%s basis=%q",
		short(r.SampleID), r.Filename, r.Version, hits, r.Verdict, r.Basis)
}

func short(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12]
}
