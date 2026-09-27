package index

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/highcumontoa/binary-analysis-index-go/pkg/binfmt"
	"github.com/highcumontoa/binary-analysis-index-go/pkg/rules"
	"github.com/highcumontoa/binary-analysis-index-go/pkg/samplegen"
)

// testLogger 把审计日志同时送到 testing 日志（满足“打印样本标识、命中规则、判定依据”）。
type testLogger struct{ t *testing.T }

func (l testLogger) Printf(format string, args ...any) {
	l.t.Logf("AUDIT "+format, args...)
}

func newTestIndex(t *testing.T, store Store, version string) *Index {
	t.Helper()
	eng, err := rules.BuiltinEngine(version)
	if err != nil {
		t.Fatal(err)
	}
	return New(Config{Engine: eng, Store: store, Logger: testLogger{t}})
}

func goodPE() []byte {
	b, err := samplegen.PE32Plus(samplegen.Spec{
		Sections: []string{"UPX1"},
		Imports:  map[string][]string{"KERNEL32.dll": {"CreateFileW", "WriteFile"}},
	})
	if err != nil {
		panic(err)
	}
	return b
}

func TestIncrementalDoesNotReanalyze(t *testing.T) {
	store := NewMemoryStore()
	idx := newTestIndex(t, store, rules.Version2)
	data := goodPE()
	id := ContentID(data)

	r1, err := idx.Analyze(context.Background(), "good.exe", data)
	if err != nil {
		t.Fatal(err)
	}
	first := r1.AnalyzedAt
	all, _ := idx.All(context.Background())
	if len(all) != 1 {
		t.Fatalf("want 1 record, got %d", len(all))
	}

	time.Sleep(2 * time.Millisecond)
	r2, err := idx.Analyze(context.Background(), "good.exe", data)
	if err != nil {
		t.Fatal(err)
	}
	if r1 != r2 {
		t.Fatal("expected same record instance / content reused")
	}
	if !r2.AnalyzedAt.Equal(first) {
		t.Fatal("record was recomputed despite identical content")
	}
	if got, _ := idx.Get(context.Background(), id); got != r1 {
		t.Fatal("Get returned different record than Analyze")
	}
}

func TestFailuresAreExplicitAndDistinguishable(t *testing.T) {
	store := NewMemoryStore()
	idx := newTestIndex(t, store, rules.Version1)

	cases := []struct {
		name string
		data []byte
		kind string
	}{
		{"plain-text", []byte("not a binary"), "unrecognized"},
		{"truncated-elf", genELF(t, samplegen.Spec{Sections: []string{".text"}, TruncateAt: 30}), "truncated"},
		{"bad-class-elf", genELF(t, samplegen.Spec{Sections: []string{".text"}, Corrupt: "class"}), "unsupported"},
		{"corrupt-pe", genPE(t, samplegen.Spec{Imports: map[string][]string{"a.dll": {"f"}}, Corrupt: "coff-signature"}), "corrupt"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec, err := idx.Analyze(context.Background(), c.name, c.data)
			if err != nil {
				t.Fatalf("failure must be recorded, not returned as hard error: %v", err)
			}
			if rec.Status != StatusFailed || rec.Failure == nil {
				t.Fatalf("want failed record, got %+v", rec)
			}
			if rec.Failure.Kind != c.kind {
				t.Fatalf("kind: want %s, got %s (ctx=%q)", c.kind, rec.Failure.Kind, rec.Failure.Context)
			}
			if rec.Failure.Context == "" {
				t.Fatalf("failure lacks locatable context: %+v", rec.Failure)
			}
			if c.kind == "truncated" && rec.Failure.Offset < 0 {
				t.Fatalf("truncated failure should carry an offset: %+v", rec.Failure)
			}
			t.Logf("sample=%s id=%s failure-kind=%s offset=%d basis=%q",
				c.name, shortID(rec.ContentID), rec.Failure.Kind, rec.Failure.Offset, rec.Failure.Context)
		})
	}
	// 失败记录也做增量：同样的坏内容不应被重复解析
	bad := []byte("not a binary")
	r1, _ := idx.Analyze(context.Background(), "a", bad)
	r2, _ := idx.Analyze(context.Background(), "a", bad)
	if r1 != r2 {
		t.Fatal("failed record not reused for identical bad content")
	}
}

func TestRuleFailureProducesFailedRecord(t *testing.T) {
	store := NewMemoryStore()
	eng := rules.NewEngine("broken-1", []rules.Rule{boom{}})
	idx := New(Config{Engine: eng, Store: store, Logger: testLogger{t}})
	elf, _ := samplegen.ELF64(samplegen.Spec{Sections: []string{".text"}})
	rec, err := idx.Analyze(context.Background(), "x.elf", elf)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != StatusFailed || rec.Failure == nil || rec.Failure.Kind != "rule_failed" || rec.Failure.RuleID != "BOOM_001" {
		t.Fatalf("want rule_failed/BOOM_001, got %+v", rec.Failure)
	}
}

func TestConcurrentDuplicateScanIsConsistent(t *testing.T) {
	store := NewMemoryStore()
	idx := newTestIndex(t, store, rules.Version2)
	data := goodPE()
	id := ContentID(data)

	const n = 32
	var wg sync.WaitGroup
	recs := make([]*Record, n)
	errs := make([]error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			recs[i], errs[i] = idx.Analyze(context.Background(), fmt.Sprintf("copy%d.exe", i), data)
		}(i)
	}
	close(start)
	wg.Wait()

	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("worker %d: %v", i, errs[i])
		}
		if recs[i] != recs[0] {
			t.Fatalf("worker %d got different record than worker 0", i)
		}
	}
	all, _ := idx.All(context.Background())
	if len(all) != 1 {
		t.Fatalf("index must contain exactly 1 record, got %d (no duplicates)", len(all))
	}
	if all[0].ContentID != id {
		t.Fatalf("record content id mismatch")
	}
	if all[0].Verdict != rules.VerdictSuspicious {
		t.Fatalf("UPX1 PE should be suspicious under v2, got %s", all[0].Verdict)
	}
	t.Logf("sample=copies id=%s matched=%v verdict=%s basis=%q",
		shortID(id), ruleIDs(all[0]), all[0].Verdict, all[0].Basis)
}

func TestRuleUpgradeCoexistence(t *testing.T) {
	store := NewMemoryStore()
	idx1 := newTestIndex(t, store, rules.Version1)
	idx2 := newTestIndex(t, store, rules.Version2)

	// 只导入 CreateFileW：v1 宽口径判 clean；v2 严口径判 suspicious
	data := genPE(t, samplegen.Spec{
		Imports: map[string][]string{"KERNEL32.dll": {"CreateFileW"}},
	})
	id := ContentID(data)

	r1, err := idx1.Analyze(context.Background(), "edge.exe", data)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := idx2.Analyze(context.Background(), "edge.exe", data)
	if err != nil {
		t.Fatal(err)
	}
	if r1.RuleVersion != rules.Version1 || r1.Verdict != rules.VerdictClean {
		t.Fatalf("v1 record wrong: %+v", r1)
	}
	if r2.RuleVersion != rules.Version2 || r2.Verdict != rules.VerdictSuspicious {
		t.Fatalf("v2 record wrong: %+v", r2)
	}
	// 两条版本化记录共存、无覆盖
	all, _ := idx2.All(context.Background())
	if len(all) != 2 {
		t.Fatalf("want 2 coexisting versioned records, got %d", len(all))
	}
	// 旧结论仍可按旧版本复现
	old, err := idx2.GetForVersion(context.Background(), id, rules.Version1)
	if err != nil || old.Verdict != rules.VerdictClean {
		t.Fatalf("old version result not reproducible: %v %+v", err, old)
	}
	new, err := idx1.GetForVersion(context.Background(), id, rules.Version2)
	if err != nil || new.Verdict != rules.VerdictSuspicious {
		t.Fatalf("new version result not visible: %v %+v", err, new)
	}
	if bytes.Equal([]byte(r1.Basis), []byte(r2.Basis)) && r1.Verdict == r2.Verdict {
		t.Fatal("verdicts/basis from different rule versions unexpectedly identical")
	}
	t.Logf("sample=edge.exe id=%s v1[verdict=%s basis=%q] v2[verdict=%s matched=%v basis=%q]",
		shortID(id), r1.Verdict, r1.Basis, r2.Verdict, ruleIDs(r2), r2.Basis)
}

func TestCanceledRequestDoesNotPolluteIndex(t *testing.T) {
	store := NewMemoryStore()
	idx := newTestIndex(t, store, rules.Version2)
	data := goodPE()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 预先取消
	_, err := idx.Analyze(ctx, "raced.exe", data)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}

	// 后台分离分析应完成并恰好留下 1 条完整记录（无半成品）
	deadline := time.Now().Add(3 * time.Second)
	var recs []*Record
	for time.Now().Before(deadline) {
		recs, _ = idx.All(context.Background())
		if len(recs) == 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if len(recs) != 1 {
		t.Fatalf("detached analysis must leave exactly 1 complete record, got %d", len(recs))
	}
	if recs[0].Status != StatusOK || recs[0].ContentID != ContentID(data) {
		t.Fatalf("detached record incomplete: %+v", recs[0])
	}

	// 再次分析必须命中已有记录而不是重算
	r, err := idx.Analyze(context.Background(), "raced.exe", data)
	if err != nil {
		t.Fatal(err)
	}
	if r != recs[0] {
		t.Fatal("record after cancellation should be reused")
	}
}

func genELF(t *testing.T, spec samplegen.Spec) []byte {
	t.Helper()
	b, err := samplegen.ELF64(spec)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func genPE(t *testing.T, spec samplegen.Spec) []byte {
	t.Helper()
	b, err := samplegen.PE32Plus(spec)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type boom struct{}

func (boom) ID() string               { return "BOOM_001" }
func (boom) Severity() rules.Severity { return rules.SeverityHigh }
func (boom) Eval(context.Context, *binfmt.BinaryInfo) (bool, string, string, error) {
	return false, "", "", errors.New("boom")
}

func ruleIDs(r *Record) []string {
	out := make([]string, len(r.Matches))
	for i, m := range r.Matches {
		out[i] = m.RuleID
	}
	return out
}

// TestConcurrentMixedCancel 混合并发：多个请求分析同一内容，部分提前取消，
// 最终索引必须恰好一条完整、结论一致的记录。
func TestConcurrentMixedCancel(t *testing.T) {
	store := NewMemoryStore()
	idx := newTestIndex(t, store, rules.Version2)
	data := goodPE()

	const n = 16
	var wg sync.WaitGroup
	verdicts := make([]string, n)
	errs := make([]error, n)
	start := make(chan struct{})
	canceledCtx, cancelAll := context.WithCancel(context.Background())
	cancelAll() // 取消型 worker 使用确定的预取消 ctx，避免取消时机竞态
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			ctx := context.Background()
			if i%3 == 0 {
				ctx = canceledCtx
			}
			r, err := idx.Analyze(ctx, fmt.Sprintf("mix%d.exe", i), data)
			errs[i] = err
			if r != nil {
				verdicts[i] = string(r.Verdict)
			}
		}(i)
	}
	close(start)
	wg.Wait()

	ok := 0
	canceled := 0
	for i := 0; i < n; i++ {
		switch {
		case errs[i] == nil:
			ok++
			if verdicts[i] != string(rules.VerdictSuspicious) {
				t.Fatalf("worker %d inconsistent verdict %q", i, verdicts[i])
			}
		case errors.Is(errs[i], context.Canceled):
			canceled++
		default:
			t.Fatalf("worker %d unexpected err %v", i, errs[i])
		}
	}
	if canceled == 0 {
		t.Fatal("test setup failed: no worker observed cancellation")
	}
	// 等待脱离的分析收尾
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if all, _ := idx.All(context.Background()); len(all) == 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	all, _ := idx.All(context.Background())
	if len(all) != 1 || all[0].Status != StatusOK || all[0].Verdict != rules.VerdictSuspicious {
		t.Fatalf("post-cancel state must be one complete suspicious record, got %+v", all)
	}
}
