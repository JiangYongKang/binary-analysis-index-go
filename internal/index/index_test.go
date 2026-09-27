package index_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/highcumontoa/binary-analysis-index-go/internal/analysis"
	"github.com/highcumontoa/binary-analysis-index-go/internal/index"
	"github.com/highcumontoa/binary-analysis-index-go/internal/rules"
)

// TestIncrementalNoReanalysis: identical content under the same rule version
// is analysed exactly once, even across many requests.
func TestIncrementalNoReanalysis(t *testing.T) {
	env := newEnv(t)
	fn, calls := countingAnalyzer(env.reg)
	idx, err := index.New(fn)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	sampleID, _ := mustHash(t, env.set.ELFDebug)

	for i := 0; i < 5; i++ {
		rec, err := idx.Scan(ctx, env.set.ELFDebug, sampleID, rules.VersionV1)
		if err != nil {
			t.Fatalf("scan #%d: %v", i, err)
		}
		if rec.Status != index.StatusSuccess || rec.Verdict != string(analysis.Clean) {
			t.Fatalf("unexpected record: %+v", rec)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("analyzer invoked %d times, want exactly 1", got)
	}
	t.Logf("incremental: 5 scans of sample=%s rules=%s -> 1 analysis", short(sampleID), rules.VersionV1)
}

// TestCorruptInputsAreClassifiedAndCached: each bad input yields a
// distinguishable failure reason and the failure itself is cached (no
// re-analysis).
func TestCorruptInputsAreClassifiedAndCached(t *testing.T) {
	env := newEnv(t)
	fn, calls := countingAnalyzer(env.reg)
	idx, err := index.New(fn)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	cases := []struct {
		path string
		kind analysis.FailureKind
	}{
		{env.set.ELFTruncated, analysis.FailureTruncated},
		{env.set.PETruncated, analysis.FailureTruncated},
		{env.set.CorruptHeader, analysis.FailureCorrupt},
		{env.set.CorruptMagic, analysis.FailureUnsupportedFormat},
		{env.set.Unsupported, analysis.FailureUnsupportedFormat},
		{env.set.Empty, analysis.FailureUnsupportedFormat},
	}
	for _, tc := range cases {
		id, _ := mustHash(t, tc.path)
		rec, err := idx.Scan(ctx, tc.path, id, rules.VersionV1)
		if err != nil {
			t.Fatalf("%s: %v", tc.path, err)
		}
		if rec.Status != index.StatusFailed {
			t.Fatalf("%s: expected failed record, got %+v", tc.path, rec)
		}
		if analysis.FailureKind(rec.Error.Kind) != tc.kind {
			t.Fatalf("%s: kind=%s want %s", tc.path, rec.Error.Kind, tc.kind)
		}
		if rec.Error.Offset < 0 || rec.Error.Message == "" {
			t.Fatalf("%s: failure lacks locatable context: %+v", tc.path, rec.Error)
		}
		logRecord(t, rec)

		// Second scan must hit the cached failure, not re-run analysis.
		if _, err := idx.Scan(ctx, tc.path, id, rules.VersionV1); err != nil {
			t.Fatalf("rescan %s: %v", tc.path, err)
		}
	}
	if got := calls.Load(); got != int64(len(cases)) {
		t.Fatalf("analyzer calls=%d want %d (failures must be cached too)", got, len(cases))
	}
}

// TestConcurrentDuplicateScan: N concurrent scans of the same target share
// one analysis and all see an identical result; no duplicate records appear.
func TestConcurrentDuplicateScan(t *testing.T) {
	env := newEnv(t)
	fn, calls := countingAnalyzer(env.reg)
	idx, err := index.New(fn)
	if err != nil {
		t.Fatal(err)
	}
	sampleID, _ := mustHash(t, env.set.PEGUI)

	const n = 32
	var wg sync.WaitGroup
	results := make([]*index.Record, n)
	errs := make([]error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i], errs[i] = idx.Scan(context.Background(), env.set.PEGUI, sampleID, rules.VersionV2)
		}(i)
	}
	close(start)
	wg.Wait()

	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("goroutine %d: %v", i, errs[i])
		}
		if results[i] != results[0] {
			t.Fatalf("goroutine %d got a different result pointer; conclusions must be identical", i)
		}
		if results[i].Verdict != string(analysis.Clean) {
			t.Fatalf("unexpected verdict %s", results[i].Verdict)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("analyzer invoked %d times under concurrency, want 1", got)
	}
	if idx.Count() != 1 {
		t.Fatalf("index has %d records, want 1 (no duplicates)", idx.Count())
	}
	logRecord(t, results[0])
}

// TestRuleVersionCoexistence: same content analysed under v1 and v2 yields
// both verdicts side by side, each clearly labelled with its rule version;
// the old v1 result stays reproducible.
func TestRuleVersionCoexistence(t *testing.T) {
	env := newEnv(t)
	fn, calls := countingAnalyzer(env.reg)
	idx, err := index.New(fn)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	sampleID, _ := mustHash(t, env.set.ELFStripped)

	r1, err := idx.Scan(ctx, env.set.ELFStripped, sampleID, rules.VersionV1)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := idx.Scan(ctx, env.set.ELFStripped, sampleID, rules.VersionV2)
	if err != nil {
		t.Fatal(err)
	}
	if r1.Version != rules.VersionV1 || r1.Verdict != string(analysis.Clean) {
		t.Fatalf("v1 result wrong: %+v", r1)
	}
	if r2.Version != rules.VersionV2 || r2.Verdict != string(analysis.Suspicious) {
		t.Fatalf("v2 result wrong: %+v", r2)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("expected exactly 2 analyses (one per version), got %d", got)
	}
	if idx.Count() != 2 {
		t.Fatalf("expected 2 coexisting records, got %d", idx.Count())
	}
	// Reproducibility: re-querying v1 must return the original clean verdict.
	again, ok := idx.Lookup(sampleID, rules.VersionV1)
	if !ok || again.Verdict != string(analysis.Clean) {
		t.Fatalf("old v1 result not reproducible: ok=%v rec=%+v", ok, again)
	}
	all := idx.LookupAnyVersion(sampleID)
	if len(all) != 2 {
		t.Fatalf("LookupAnyVersion=%d want 2", len(all))
	}
	logRecord(t, r1)
	logRecord(t, r2)
}

// TestCancelledCallerDoesNotPollute: a waiter that gives up receives its own
// context error, but the shared analysis completes and its result is
// committed; a subsequent scan sees the complete record and no extra
// analysis runs.
func TestCancelledCallerDoesNotPollute(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var ran atomic.Int32
	blocking := index.AnalyzerFunc(func(ctx context.Context, file, sampleID, version string) (*analysis.Result, error) {
		ran.Add(1)
		close(entered) // analysis goroutine has definitely started
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return &analysis.Result{SampleID: sampleID, Filename: file, Version: version,
			Verdict: analysis.Clean, Basis: "unblocked"}, nil
	})
	idx, err := index.New(blocking)
	if err != nil {
		t.Fatal(err)
	}
	sampleID := "deadbeef"

	// First request starts the (slow) shared analysis.
	go func() {
		idx.Scan(context.Background(), "file", sampleID, rules.VersionV1)
	}()
	<-entered // deterministic: the in-flight analysis exists now

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err = idx.Scan(ctx, "file", sampleID, rules.VersionV1)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want DeadlineExceeded, got %v", err)
	}

	// Index must not carry a half-finished record for the abandoned wait.
	if idx.Count() != 0 {
		t.Fatalf("cancelled wait left %d records, want 0", idx.Count())
	}
	if _, ok := idx.Lookup(sampleID, rules.VersionV1); ok {
		t.Fatal("cancelled wait left a visible half record")
	}

	// Let the shared analysis finish; it must commit exactly once.
	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if rec, ok := idx.Lookup(sampleID, rules.VersionV1); ok {
			if rec.Status != index.StatusSuccess {
				t.Fatalf("committed record not successful: %+v", rec)
			}
			if ran.Load() != 1 {
				t.Fatalf("shared analysis ran %d times, want 1", ran.Load())
			}
			logRecord(t, rec)
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("shared analysis result was never committed after cancellation")
}

// TestPersistenceRoundTrip: records survive reopening the index and are not
// re-analysed.
func TestPersistenceRoundTrip(t *testing.T) {
	env := newEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "index.json")

	fn1, calls1 := countingAnalyzer(env.reg)
	idx1, err := index.New(fn1, index.WithStore(index.NewFileStore(path)))
	if err != nil {
		t.Fatal(err)
	}
	id1, _ := mustHash(t, env.set.ELFDebug)
	id2, _ := mustHash(t, env.set.PEGUI)
	if _, err := idx1.Scan(context.Background(), env.set.ELFDebug, id1, rules.VersionV2); err != nil {
		t.Fatal(err)
	}
	if _, err := idx1.Scan(context.Background(), env.set.PEGUI, id2, rules.VersionV2); err != nil {
		t.Fatal(err)
	}
	if calls1.Load() != 2 {
		t.Fatalf("calls=%d want 2", calls1.Load())
	}

	// Reopen: persisted state is loaded and reused with zero re-analysis.
	fn2, calls2 := countingAnalyzer(env.reg)
	idx2, err := index.New(fn2, index.WithStore(index.NewFileStore(path)))
	if err != nil {
		t.Fatal(err)
	}
	if idx2.Count() != 2 {
		t.Fatalf("reloaded count=%d want 2", idx2.Count())
	}
	rec, err := idx2.Scan(context.Background(), env.set.ELFDebug, id1, rules.VersionV2)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Verdict != string(analysis.Clean) {
		t.Fatalf("reloaded verdict=%s", rec.Verdict)
	}
	if calls2.Load() != 0 {
		t.Fatalf("reopened index re-ran %d analyses, want 0", calls2.Load())
	}
	logRecord(t, rec)
}

// TestInterruptedUpdateRecovery: a leftover temp file from an interrupted
// save is ignored; the last complete snapshot remains intact, and there are
// no dangling or duplicate records.
func TestInterruptedUpdateRecovery(t *testing.T) {
	env := newEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "index.json")

	fn, _ := countingAnalyzer(env.reg)
	idx, err := index.New(fn, index.WithStore(index.NewFileStore(path)))
	if err != nil {
		t.Fatal(err)
	}
	id, _ := mustHash(t, env.set.ELFDebug)
	rec, err := idx.Scan(context.Background(), env.set.ELFDebug, id, rules.VersionV2)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate a crash during a later Save: drop a partial temp file and
	// corrupt no existing file.
	tmp := filepath.Join(dir, "index.json.tmp-crashed")
	if err := os.WriteFile(tmp, []byte("{\"generation\": 99, \"records\": {partial"), 0o644); err != nil {
		t.Fatal(err)
	}

	reloaded, err := index.New(fn, index.WithStore(index.NewFileStore(path)))
	if err != nil {
		t.Fatalf("recovery failed: %v", err)
	}
	if reloaded.Count() != 1 {
		t.Fatalf("after recovery count=%d want 1 (old complete state)", reloaded.Count())
	}
	got, ok := reloaded.Lookup(id, rules.VersionV2)
	if !ok || got.Verdict != rec.Verdict || got.Basis != rec.Basis {
		t.Fatalf("recovered record differs: ok=%v got=%+v", ok, got)
	}

	// A subsequent successful save replaces state cleanly; only one snapshot
	// file remains (temp files are cleaned up).
	id2, _ := mustHash(t, env.set.PEGUI)
	if _, err := reloaded.Scan(context.Background(), env.set.PEGUI, id2, rules.VersionV2); err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("dangling files after recovery: %v", names)
	}
	logRecord(t, got)
}
