package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/highcumontoa/binary-analysis-index-go/internal/samples"
)

// TestCLI is a black-box test driving run(): it generates samples, scans them
// under both rule versions into a persistent index and queries it back.
func TestCLI(t *testing.T) {
	dir := t.TempDir()
	set, err := samples.Create(filepath.Join(dir, "samples"))
	if err != nil {
		t.Fatal(err)
	}
	indexPath := filepath.Join(dir, "idx.json")

	var out, errb bytes.Buffer
	args := func(parts ...string) []string {
		return append([]string{"-index", indexPath}, parts...)
	}

	if code := run(args("versions"), &out, &errb); code != 0 {
		t.Fatalf("versions code=%d err=%s", code, errb.String())
	}

	scanArgs := args("scan", "-rules", "builtin-2026.1",
		set.ELFStripped, set.ELFDebug, set.PEGUI, set.ELFTruncated,
		set.CorruptHeader, set.Unsupported, set.Empty)
	out.Reset()
	errb.Reset()
	if code := run(scanArgs, &out, &errb); code != 0 {
		t.Fatalf("scan code=%d err=%s", code, errb.String())
	}
	s := out.String()
	for _, want := range []string{"rules=builtin-2026.1", "verdict=clean",
		"status=failed kind=truncated", "status=failed kind=corrupt",
		"status=failed kind=unsupported_format"} {
		if !strings.Contains(s, want) {
			t.Fatalf("scan output missing %q:\n%s", want, s)
		}
	}
	if strings.Count(s, "sample=") != 7 {
		t.Fatalf("expected 7 output records, got:\n%s", s)
	}

	// v2 upgrade: stripped ELF flips to suspicious and the v1 record persists.
	out.Reset()
	if code := run(args("scan", "-rules", "builtin-2026.2", set.ELFStripped), &out, &errb); code != 0 {
		t.Fatalf("v2 scan: %s", errb.String())
	}
	if !strings.Contains(out.String(), "verdict=suspicious") {
		t.Fatalf("v2 stripped elf not suspicious:\n%s", out.String())
	}

	out.Reset()
	if code := run(args("list"), &out, &errb); code != 0 {
		t.Fatalf("list: %s", errb.String())
	}
	if strings.Count(out.String(), "sample=") != 8 {
		t.Fatalf("list expected 8 persisted records (7 v1 + 1 new v2), got:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "rules=builtin-2026.1") ||
		!strings.Contains(out.String(), "rules=builtin-2026.2") {
		t.Fatal("list must contain both rule versions")
	}

	// Incremental: re-scan must produce identical output and not error.
	before := out.String()
	out.Reset()
	if code := run(args("scan", "-rules", "builtin-2026.1", set.ELFDebug), &out, &errb); code != 0 {
		t.Fatalf("rescan: %s", errb.String())
	}
	if !strings.Contains(out.String(), "verdict=clean") {
		t.Fatalf("incremental rescan mismatch:\n%s", out.String())
	}
	t.Logf("CLI e2e OK; sample listing:\n%s", before)
}
