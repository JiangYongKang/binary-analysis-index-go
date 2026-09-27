package scan_test

import (
	"context"
	"sync"
	"testing"

	"github.com/highcumontoa/binary-analysis-index-go/internal/analysis"
	"github.com/highcumontoa/binary-analysis-index-go/internal/index"
	"github.com/highcumontoa/binary-analysis-index-go/internal/rules"
	"github.com/highcumontoa/binary-analysis-index-go/internal/samples"
	"github.com/highcumontoa/binary-analysis-index-go/internal/scan"
)

func newService(t *testing.T, store index.Store) (*scan.Service, *samples.Set) {
	t.Helper()
	set, err := samples.Create(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	reg := rules.NewRegistry()
	reg.MustRegister(rules.BuiltinV1())
	reg.MustRegister(rules.BuiltinV2())
	az := analysis.NewAnalyzer(reg)
	svc0 := scan.New(az, nil)
	var opts []index.Option
	if store != nil {
		opts = append(opts, index.WithStore(store))
	}
	idx, err := index.New(svc0.AnalyzerFunc(), opts...)
	if err != nil {
		t.Fatal(err)
	}
	return scan.New(az, idx), set
}

// TestContentAddressing: two different filenames holding identical bytes map
// to the same sample identity and are analysed once per rule version.
func TestContentAddressing(t *testing.T) {
	svc, set := newService(t, nil)
	ctx := context.Background()

	// Make a second path with identical content but a different name.
	copyPath := set.Dir + "/copy_of_debug.bin"
	data := readFile(t, set.ELFDebug)
	writeFile(t, copyPath, data)

	r1, err := svc.ScanFile(ctx, set.ELFDebug, rules.VersionV1)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := svc.ScanFile(ctx, copyPath, rules.VersionV1)
	if err != nil {
		t.Fatal(err)
	}
	if r1.SampleID != r2.SampleID {
		t.Fatalf("identical content produced different ids: %s vs %s", r1.SampleID, r2.SampleID)
	}
	if r1 != r2 {
		t.Fatal("identical content re-analysed under a different filename")
	}
	if svc.Index().Count() != 1 {
		t.Fatalf("index count=%d want 1 (content-addressed)", svc.Index().Count())
	}
	t.Logf("sample=%s filenames=%q,%q share one record verdict=%s",
		r1.SampleID[:12], r1.Filename, r2.Filename, r1.Verdict)
}

// TestEndToEndConcurrentAndVersions combines concurrency, incremental reuse
// and version coexistence through the public scan API.
func TestEndToEndConcurrentAndVersions(t *testing.T) {
	svc, set := newService(t, nil)
	const n = 16
	var wg sync.WaitGroup
	errs := make([]error, n)
	recs := make([]*index.Record, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			recs[i], errs[i] = svc.ScanFile(context.Background(), set.ELFStripped, rules.VersionV2)
		}(i)
	}
	close(start)
	wg.Wait()
	for i := range errs {
		if errs[i] != nil {
			t.Fatalf("%d: %v", i, errs[i])
		}
		if recs[i].Verdict != string(analysis.Suspicious) {
			t.Fatalf("got %s", recs[i].Verdict)
		}
	}
	// Same file under v1 coexists.
	r1, err := svc.ScanFile(context.Background(), set.ELFStripped, rules.VersionV1)
	if err != nil {
		t.Fatal(err)
	}
	if r1.Verdict != string(analysis.Clean) {
		t.Fatalf("v1 verdict=%s", r1.Verdict)
	}
	if svc.Index().Count() != 2 {
		t.Fatalf("count=%d want 2 versions", svc.Index().Count())
	}
	t.Logf("sample=%s v1=%s v2=%s after %d concurrent requests",
		recs[0].SampleID[:12], r1.Verdict, recs[0].Verdict, n)
}

func readFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := readFileOS(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func writeFile(t *testing.T, p string, b []byte) {
	t.Helper()
	if err := writeFileOS(p, b); err != nil {
		t.Fatal(err)
	}
}
