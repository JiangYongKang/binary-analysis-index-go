package binaryfmt_test

import (
	"os"
	"testing"

	"github.com/highcumontoa/binary-analysis-index-go/internal/binaryfmt"
	"github.com/highcumontoa/binary-analysis-index-go/internal/samples"
)

func openSample(t *testing.T, path string) (*os.File, int64) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	st, err := f.Stat()
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return f, st.Size()
}

func TestParseSmoke(t *testing.T) {
	set, err := samples.Create(t.TempDir())
	if err != nil {
		t.Fatalf("samples: %v", err)
	}
	cases := []struct {
		path     string
		wantErr  bool
		wantFmt  binaryfmt.Format
		reason   binaryfmt.FailureReason
		stripped bool
	}{
		{path: set.ELFStripped, wantFmt: binaryfmt.FormatELF, stripped: true},
		{path: set.ELFDebug, wantFmt: binaryfmt.FormatELF, stripped: false},
		{path: set.PEConsole, wantFmt: binaryfmt.FormatPE},
		{path: set.PEGUI, wantFmt: binaryfmt.FormatPE},
		{path: set.PEStripped, wantFmt: binaryfmt.FormatPE, stripped: true},
		{path: set.ELFTruncated, wantErr: true, reason: binaryfmt.ReasonTruncated},
		{path: set.PETruncated, wantErr: true, reason: binaryfmt.ReasonTruncated},
		{path: set.CorruptMagic, wantErr: true, reason: binaryfmt.ReasonUnsupportedFormat},
		{path: set.CorruptHeader, wantErr: true, reason: binaryfmt.ReasonCorrupt},
		{path: set.Unsupported, wantErr: true, reason: binaryfmt.ReasonUnsupportedFormat},
		{path: set.Empty, wantErr: true, reason: binaryfmt.ReasonUnsupportedFormat},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			f, size := openSample(t, tc.path)
			defer f.Close()
			info, err := binaryfmt.Parse(tc.path, f, size)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got info %+v", info)
				}
				pe, ok := binaryfmt.AsParseError(err)
				if !ok {
					t.Fatalf("expected *ParseError, got %T %v", err, err)
				}
				if pe.Reason != tc.reason {
					t.Fatalf("reason=%s want %s (%s)", pe.Reason, tc.reason, pe)
				}
				t.Logf("sample=%s classified failure reason=%s at offset=%d: %s",
					tc.path, pe.Reason, pe.Offset, pe.Detail)
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if info.Format != tc.wantFmt {
				t.Fatalf("format=%s want %s", info.Format, tc.wantFmt)
			}
			if info.Stripped != tc.stripped {
				t.Fatalf("stripped=%v want %v; sections=%v", info.Stripped, tc.stripped, info.Sections)
			}
			t.Logf("sample=%s format=%s class=%s machine=%s sections=%d stripped=%v",
				tc.path, info.Format, info.Class, info.Machine, len(info.Sections), info.Stripped)
		})
	}
}
