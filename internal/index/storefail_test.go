package index_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/highcumontoa/binary-analysis-index-go/internal/index"
	"github.com/highcumontoa/binary-analysis-index-go/internal/rules"
)

// failFirstStore fails Save the first failTimes times it is called, then
// delegates to the wrapped store.
type failFirstStore struct {
	inner    index.Store
	failLeft int32
}

func (s *failFirstStore) Load() (*index.Snapshot, error) { return s.inner.Load() }

func (s *failFirstStore) Save(snap *index.Snapshot) error {
	if atomic.AddInt32(&s.failLeft, -1) >= 0 {
		return errors.New("simulated disk full")
	}
	return s.inner.Save(snap)
}

// TestPersistenceFailureKeepsOldState: when Save fails the scan returns an
// error, nothing is published, and the index stays at the previous complete
// state. A later retry succeeds and commits; no half record is ever visible.
func TestPersistenceFailureKeepsOldState(t *testing.T) {
	env := newEnv(t)
	fn, calls := countingAnalyzer(env.reg)
	store := &failFirstStore{
		inner:    index.NewFileStore(t.TempDir() + "/index.json"),
		failLeft: 1, // fail the very first Save
	}
	idx, err := index.New(fn, index.WithStore(store))
	if err != nil {
		t.Fatal(err)
	}

	id1, _ := mustHash(t, env.set.ELFDebug)
	if _, err := idx.Scan(context.Background(), env.set.ELFDebug, id1, rules.VersionV1); err == nil {
		t.Fatal("expected persistence error, got nil")
	}
	if idx.Count() != 0 {
		t.Fatalf("failed publish left %d records, want 0 (no half state)", idx.Count())
	}
	if _, ok := idx.Lookup(id1, rules.VersionV1); ok {
		t.Fatal("a half-finished record became visible after Save failure")
	}

	// Retry: flight must have been cleaned up and the retry must commit.
	rec, err := idx.Scan(context.Background(), env.set.ELFDebug, id1, rules.VersionV1)
	if err != nil {
		t.Fatalf("retry failed: %v", err)
	}
	if rec.Status != index.StatusSuccess {
		t.Fatalf("retry record: %+v", rec)
	}
	if idx.Count() != 1 {
		t.Fatalf("count after retry=%d want 1", idx.Count())
	}
	// Successful commit means no further analysis on a third scan.
	if _, err := idx.Scan(context.Background(), env.set.ELFDebug, id1, rules.VersionV1); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("analyzer calls=%d want 2 (one failed publish, one retry)", calls.Load())
	}
	logRecord(t, rec)
}
