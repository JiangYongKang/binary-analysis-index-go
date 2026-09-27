package index

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"sync"
	"testing"

	"github.com/highcumontoa/binary-analysis-index-go/pkg/rules"
	"github.com/highcumontoa/binary-analysis-index-go/pkg/samplegen"
)

func TestFileStoreRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "index.json")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	idx := newTestIndex(t, store, rules.Version2)
	data, err := samplegen.PE32Plus(samplegen.Spec{
		Sections: []string{"UPX0"},
		Imports:  map[string][]string{"KERNEL32.dll": {"CreateFileW", "WriteFile"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	rec, err := idx.Analyze(context.Background(), "persist.exe", data)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store2, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	idx2 := newTestIndex(t, store2, rules.Version2)
	got, err := idx2.Get(context.Background(), rec.ContentID)
	if err != nil {
		t.Fatalf("record lost after reopen: %v", err)
	}
	if got.Verdict != rec.Verdict || got.RuleVersion != rec.RuleVersion || got.Status != StatusOK {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	again, err := idx2.Analyze(context.Background(), "persist.exe", data)
	if err != nil {
		t.Fatal(err)
	}
	if !again.AnalyzedAt.Equal(rec.AnalyzedAt) {
		t.Fatal("reopened index re-analyzed identical content")
	}
}

func TestFileStoreCrashBeforeRenameRecovery(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "index.json")

	base, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	eng, _ := rules.BuiltinEngine(rules.Version1)
	idxBase := New(Config{Engine: eng, Store: base, Logger: testLogger{t}})
	elf, _ := samplegen.ELF64(samplegen.Spec{Sections: []string{".text"}})
	if _, err := idxBase.Analyze(context.Background(), "base.elf", elf); err != nil {
		t.Fatal(err)
	}
	base.Close()

	crash := errors.New("simulated power loss")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	store.SetCrashHook(func() error { return crash })
	up, _ := samplegen.PE32Plus(samplegen.Spec{
		Imports: map[string][]string{"KERNEL32.dll": {"CreateFileW", "WriteFile"}},
	})
	id := ContentID(up)
	_, aerr := newTestIndex(t, store, rules.Version2).Analyze(context.Background(), "up.exe", up)
	if !errors.Is(aerr, crash) {
		t.Fatalf("want injected crash error, got %v", aerr)
	}
	staging, _ := filepath.Glob(path + ".tmp.*")
	if len(staging) != 1 {
		t.Fatalf("expected 1 orphan staging file, got %v", staging)
	}
	// 崩溃瞬间，读端只能看到完整旧状态，没有半成品记录
	recs, _ := store.Snapshot(context.Background())
	if len(recs) != 1 {
		t.Fatalf("after crash readers must see only the complete old state, got %d records", len(recs))
	}
	if _, ok := recs[RecordKey(ContentID(elf), rules.Version1)]; !ok {
		t.Fatal("baseline record missing after crash")
	}
	store.Close()

	// 重新打开：孤儿临时文件被清理，旧状态完好，新更新可以补上
	recovered, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if left, _ := filepath.Glob(path + ".tmp.*"); len(left) != 0 {
		t.Fatalf("stale staging files not cleaned on recovery: %v", left)
	}
	idxR := newTestIndex(t, recovered, rules.Version2)
	if _, err := idxR.Analyze(context.Background(), "up.exe", up); err != nil {
		t.Fatalf("recovered store could not accept update: %v", err)
	}
	all, _ := idxR.All(context.Background())
	if len(all) != 2 {
		t.Fatalf("want 2 records (old v1 + new v2), got %d", len(all))
	}
	for _, r := range all {
		if r.Status == "" || r.RuleVersion == "" {
			t.Fatalf("half-written record detected: %+v", r)
		}
	}
	if _, err := idxR.GetForVersion(context.Background(), id, rules.Version2); err != nil {
		t.Fatalf("v2 record missing: %v", err)
	}
}

// TestSnapshotIsolationUnderConcurrentUpdates 验证读端只看到完整状态，
// 绝不读到半新半旧或重复记录。
func TestSnapshotIsolationUnderConcurrentUpdates(t *testing.T) {
	store := NewMemoryStore()
	idx := newTestIndex(t, store, rules.Version2)

	samples := make([][]byte, 12)
	ids := make([]string, 12)
	for i := range samples {
		b, err := samplegen.ELF64(samplegen.Spec{
			Sections: []string{fmt.Sprintf(".text%d", i)},
		})
		if err != nil {
			t.Fatal(err)
		}
		samples[i] = b
		ids[i] = ContentID(b)
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				snap, err := store.Snapshot(context.Background())
				if err != nil {
					t.Errorf("snapshot: %v", err)
					return
				}
				seenIDs := map[string]bool{}
				for k, r := range snap {
					if r.Status != StatusOK || r.RuleVersion != rules.Version2 || r.AnalyzedAt.IsZero() {
						t.Errorf("torn record visible: key=%s rec=%+v", k, r)
						return
					}
					seenIDs[r.ContentID] = true
				}
				if len(seenIDs) != len(snap) {
					t.Errorf("duplicate content records in one snapshot: %d ids in %d records", len(seenIDs), len(snap))
					return
				}
			}
		}()
	}
	var wg2 sync.WaitGroup
	for i, b := range samples {
		wg2.Add(1)
		go func(i int, b []byte) {
			defer wg2.Done()
			if _, err := idx.Analyze(context.Background(), fmt.Sprintf("s%d.elf", i), b); err != nil {
				t.Errorf("analyze %d: %v", i, err)
			}
		}(i, b)
	}
	wg2.Wait()
	close(stop)
	wg.Wait()

	all, _ := idx.All(context.Background())
	if len(all) != len(samples) {
		t.Fatalf("want %d final records, got %d", len(samples), len(all))
	}
	gotIDs := make([]string, len(all))
	for i, r := range all {
		gotIDs[i] = r.ContentID
	}
	sort.Strings(gotIDs)
	sort.Strings(ids)
	for i := range ids {
		if gotIDs[i] != ids[i] {
			t.Fatalf("final id set mismatch at %d", i)
		}
	}
}

func TestGetNotFound(t *testing.T) {
	idx := newTestIndex(t, NewMemoryStore(), rules.Version1)
	if _, err := idx.Get(context.Background(), "deadbeef"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}
