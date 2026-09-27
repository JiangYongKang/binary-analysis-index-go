package index_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/highcumontoa/binary-analysis-index-go/internal/analysis"
	"github.com/highcumontoa/binary-analysis-index-go/internal/index"
	"github.com/highcumontoa/binary-analysis-index-go/internal/rules"
)

// TestRuleExecutionFailureIsRecorded: a rule that errors must not be silently
// skipped. The analysis aborts and the index stores a distinguishable
// rule_execution failure naming the offending rule.
func TestRuleExecutionFailureIsRecorded(t *testing.T) {
	env := newEnv(t)

	bad := rules.NewSet("broken-1",
		&rules.BasicRule{
			ID_: "format.classified", Sev: rules.SeverityInfo,
			Check: func(ctx context.Context, f rules.Facts) (bool, error) {
				return f.Format == "elf", nil
			},
		},
		&rules.FailingRule{ID_: "boom.always", Err: errors.New("synthetic rule crash")},
	)
	if err := env.reg.Register(bad); err != nil {
		t.Fatal(err)
	}

	fn, calls := countingAnalyzer(env.reg)
	idx, err := index.New(fn)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	id, _ := mustHash(t, env.set.ELFDebug)

	rec, err := idx.Scan(ctx, env.set.ELFDebug, id, "broken-1")
	if err != nil {
		t.Fatalf("rule failure should be a failed record, not an error: %v", err)
	}
	if rec.Status != index.StatusFailed {
		t.Fatalf("status=%s want failed", rec.Status)
	}
	if rec.Error.Kind != string(analysis.FailureRuleExecution) {
		t.Fatalf("kind=%s want rule_execution", rec.Error.Kind)
	}
	if rec.Error.RuleID != "boom.always" {
		t.Fatalf("rule id=%q want boom.always", rec.Error.RuleID)
	}
	logRecord(t, rec)

	// Deterministic: a cached failure is identical on repeat and not re-run.
	again, err := idx.Scan(ctx, env.set.ELFDebug, id, "broken-1")
	if err != nil {
		t.Fatal(err)
	}
	if again.Error.RuleID != "boom.always" {
		t.Fatal("repeated rule failure produced a different record")
	}
	if calls.Load() != 1 {
		t.Fatalf("rule failure re-analysed: calls=%d want 1", calls.Load())
	}
}

// TestSnapshotConsistencyDuringUpdates: a reader observing the index while
// many updates commit always sees a complete, self-consistent generation:
// every record key resolves and counts never go backwards or appear
// half-applied.
func TestSnapshotConsistencyDuringUpdates(t *testing.T) {
	env := newEnv(t)
	fn, _ := countingAnalyzer(env.reg)
	idx, err := index.New(fn)
	if err != nil {
		t.Fatal(err)
	}
	files := []string{env.set.ELFDebug, env.set.ELFStripped, env.set.PEConsole,
		env.set.PEGUI, env.set.PEStripped, env.set.CorruptMagic, env.set.ELFTruncated}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var lastGen int
		for {
			select {
			case <-stop:
				return
			default:
			}
			snap := idx.Current()
			if snap.Generation < lastGen {
				t.Errorf("generation went backwards: %d -> %d", lastGen, snap.Generation)
				return
			}
			lastGen = snap.Generation
			// Every record in a published snapshot must be whole and match
			// its key; a half-applied update would fail this check.
			for k, r := range snap.Records {
				if r == nil || r.Key() != k {
					t.Errorf("inconsistent snapshot key=%s record=%+v", k, r)
					return
				}
				if r.Status == "" {
					t.Errorf("record %s has empty status", k)
					return
				}
			}
		}
	}()

	ctx := context.Background()
	for i := 0; i < 5; i++ {
		for _, f := range files {
			id, _ := mustHash(t, f)
			ver := rules.VersionV1
			if i%2 == 0 {
				ver = rules.VersionV2
			}
			if _, err := idx.Scan(ctx, f, id, ver); err != nil {
				t.Fatal(err)
			}
		}
	}
	close(stop)
	wg.Wait()

	// Final state: each (sample, version) appears exactly once, no
	// duplicates and no dangling records.
	want := 0
	seen := map[string]bool{}
	for _, f := range files {
		id, _ := mustHash(t, f)
		for _, v := range []string{rules.VersionV1, rules.VersionV2} {
			seen[id+"|"+v] = false
			want++
		}
	}
	snap := idx.Current()
	if len(snap.Records) != want {
		t.Fatalf("final records=%d want %d (no duplicates)", len(snap.Records), want)
	}
	for k, r := range snap.Records {
		mark := r.SampleID + "|" + r.Version
		if _, ok := seen[mark]; !ok {
			t.Fatalf("dangling/unexpected record %s", k)
		}
		seen[mark] = true
	}
	t.Logf("snapshot consistency OK over %d unique (sample,version) records", want)
}

// TestUnknownRuleVersionIsInfraError: asking for a missing rule version is an
// infrastructure error (no record cached), distinct from a classified
// sample failure.
func TestUnknownRuleVersionIsInfraError(t *testing.T) {
	env := newEnv(t)
	fn, _ := countingAnalyzer(env.reg)
	idx, err := index.New(fn)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := mustHash(t, env.set.ELFDebug)
	_, err = idx.Scan(context.Background(), env.set.ELFDebug, id, "does-not-exist")
	if err == nil {
		t.Fatal("expected error for unknown rule version")
	}
	if idx.Count() != 0 {
		t.Fatalf("infra error left %d records, want 0", idx.Count())
	}
}
