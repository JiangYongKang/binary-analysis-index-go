package analysis_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/highcumontoa/binary-analysis-index-go/internal/analysis"
	"github.com/highcumontoa/binary-analysis-index-go/internal/rules"
	"github.com/highcumontoa/binary-analysis-index-go/internal/samples"
)

func openRA(t *testing.T, path string) (*os.File, int64) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	st, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	return f, st.Size()
}

func TestAnalyzeVerdictsAndBasis(t *testing.T) {
	set, err := samples.Create(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	reg := rules.NewRegistry()
	reg.MustRegister(rules.BuiltinV1())
	reg.MustRegister(rules.BuiltinV2())
	az := analysis.NewAnalyzer(reg)

	t.Run("v1 stripped elf clean / v2 suspicious", func(t *testing.T) {
		f, sz := openRA(t, set.ELFStripped)
		defer f.Close()
		r1, err := az.Analyze(context.Background(), set.ELFStripped, f, sz, rules.VersionV1)
		if err != nil {
			t.Fatal(err)
		}
		if r1.IsFailure() || r1.Verdict != analysis.Clean {
			t.Fatalf("v1: %+v", r1)
		}
		f2, sz2 := openRA(t, set.ELFStripped)
		defer f2.Close()
		r2, err := az.Analyze(context.Background(), set.ELFStripped, f2, sz2, rules.VersionV2)
		if err != nil {
			t.Fatal(err)
		}
		if r2.Verdict != analysis.Suspicious {
			t.Fatalf("v2 verdict=%s want suspicious", r2.Verdict)
		}
		if r2.Version != rules.VersionV2 {
			t.Fatalf("result not labelled with rule version: %s", r2.Version)
		}
		var found bool
		for _, m := range r2.Matches {
			if m.RuleID == "elf.stripped" {
				found = true
			}
		}
		if !found {
			t.Fatal("v2 matches lack elf.stripped")
		}
		t.Logf("sample=%s v1=%s v2=%s basis=%q", set.ELFStripped, r1.Verdict, r2.Verdict, r2.Basis)
	})

	t.Run("failures distinguishable", func(t *testing.T) {
		cases := []struct {
			path string
			kind analysis.FailureKind
		}{
			{set.ELFTruncated, analysis.FailureTruncated},
			{set.PETruncated, analysis.FailureTruncated},
			{set.CorruptHeader, analysis.FailureCorrupt},
			{set.CorruptMagic, analysis.FailureUnsupportedFormat},
			{set.Unsupported, analysis.FailureUnsupportedFormat},
			{set.Empty, analysis.FailureUnsupportedFormat},
		}
		for _, tc := range cases {
			f, sz := openRA(t, tc.path)
			res, err := az.Analyze(context.Background(), tc.path, f, sz, rules.VersionV2)
			f.Close()
			if err != nil {
				t.Fatalf("%s: unexpected infra error %v", tc.path, err)
			}
			if !res.IsFailure() {
				t.Fatalf("%s: expected failed result", tc.path)
			}
			if res.Failed.Kind != tc.kind {
				t.Fatalf("%s: kind=%s want %s", tc.path, res.Failed.Kind, tc.kind)
			}
			t.Logf("sample=%s kind=%s offset=%d detail=%q", tc.path, res.Failed.Kind, res.Failed.Offset, res.Failed.Message)
		}
	})
}

func TestRuleFailureAborts(t *testing.T) {
	set, err := samples.Create(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	reg := rules.NewRegistry()
	reg.MustRegister(rules.NewSet("x-1", &rules.FailingRule{ID_: "r.boom", Err: errors.New("boom")}))
	az := analysis.NewAnalyzer(reg)
	f, sz := openRA(t, set.ELFDebug)
	defer f.Close()
	res, err := az.Analyze(context.Background(), set.ELFDebug, f, sz, "x-1")
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsFailure() || res.Failed.Kind != analysis.FailureRuleExecution || res.Failed.RuleID != "r.boom" {
		t.Fatalf("unexpected: %+v", res)
	}
	t.Logf("rule failure recorded: rule=%s msg=%q", res.Failed.RuleID, res.Failed.Message)
}

func TestCancellationReturnsNoResult(t *testing.T) {
	set, err := samples.Create(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	reg := rules.NewRegistry()
	// A slow rule lets us cancel mid-evaluation.
	reg.MustRegister(rules.NewSet("slow-1", &rules.BasicRule{
		ID_: "slow.rule",
		Check: func(ctx context.Context, f rules.Facts) (bool, error) {
			<-ctx.Done()
			return false, ctx.Err()
		},
	}))
	az := analysis.NewAnalyzer(reg)
	f, sz := openRA(t, set.ELFDebug)
	defer f.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := az.Analyze(ctx, set.ELFDebug, f, sz, "slow-1")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got res=%+v err=%v", res, err)
	}
	if res != nil {
		t.Fatal("cancelled analysis must not return a partial result")
	}
}

func TestUnknownVersionInfraError(t *testing.T) {
	set, _ := samples.Create(t.TempDir())
	reg := rules.NewRegistry()
	az := analysis.NewAnalyzer(reg)
	f, sz := openRA(t, set.ELFDebug)
	defer f.Close()
	_, err := az.Analyze(context.Background(), set.ELFDebug, f, sz, "nope")
	if err == nil {
		t.Fatal("expected error for unknown version")
	}
}
