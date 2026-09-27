package binfmt

import (
	"testing"

	"github.com/highcumontoa/binary-analysis-index-go/pkg/samplegen"
)

func TestParseELF64(t *testing.T) {
	data, err := samplegen.ELF64(samplegen.Spec{Sections: []string{".text", ".upx0"}})
	if err != nil {
		t.Fatal(err)
	}
	info, err := Parse(data, "sample.elf")
	if err != nil {
		t.Fatalf("expected parse success, got %v", err)
	}
	if info.Format != FormatELF || info.Bits != 64 || info.Arch != "amd64" {
		t.Fatalf("unexpected header: %+v", info)
	}
	var foundUPX bool
	for _, s := range info.Sections {
		if s.Name == ".upx0" {
			foundUPX = s.IsUPXLike
			if s.Entropy < 7.0 {
				t.Fatalf("upx section entropy too low: %.2f", s.Entropy)
			}
		}
	}
	if !foundUPX {
		t.Fatal("section .upx0 not marked UPX-like")
	}
}

func TestParsePE32Plus(t *testing.T) {
	data, err := samplegen.PE32Plus(samplegen.Spec{
		Sections: []string{"UPX1"},
		Imports:  map[string][]string{"KERNEL32.dll": {"CreateFileW", "WriteFile"}, "msvcrt.dll": {"printf"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	info, err := Parse(data, "sample.exe")
	if err != nil {
		t.Fatalf("expected parse success, got %v", err)
	}
	if info.Format != FormatPE || info.Bits != 64 || info.Arch != "amd64" || info.Type != "exe" {
		t.Fatalf("unexpected header: %+v", info)
	}
	if got := info.Imports["KERNEL32.dll"]; len(got) != 2 || got[0] != "CreateFileW" || got[1] != "WriteFile" {
		t.Fatalf("bad KERNEL32 imports: %v", got)
	}
	if len(info.Imports["msvcrt.dll"]) != 1 || info.Imports["msvcrt.dll"][0] != "printf" {
		t.Fatalf("bad msvcrt imports: %v", info.Imports["msvcrt.dll"])
	}
	var upx bool
	for _, s := range info.Sections {
		if s.Name == "UPX1" && s.IsUPXLike && s.Entropy >= 7.0 {
			upx = true
		}
	}
	if !upx {
		t.Fatal("UPX1 section not recognized as high-entropy packed section")
	}
}

func TestParseErrorsAreDistinguishable(t *testing.T) {
	// 完全不支持的格式
	if _, err := Parse([]byte("hello world this is plain text"), "x"); !IsKind(err, FailureUnrecognized) {
		t.Fatalf("want unrecognized, got %v", err)
	}
	// 空文件
	if _, err := Parse(nil, "x"); !IsKind(err, FailureUnrecognized) {
		t.Fatalf("empty file want unrecognized, got %v", err)
	}

	// ELF：非法 class -> unsupported
	elfBad, _ := samplegen.ELF64(samplegen.Spec{Sections: []string{".text"}, Corrupt: "class"})
	if _, err := Parse(elfBad, "x"); !IsKind(err, FailureUnsupported) {
		t.Fatalf("want unsupported, got %v", err)
	}
	// ELF：节偏移越界 -> truncated（而不是 corrupt）
	elfTr, _ := samplegen.ELF64(samplegen.Spec{Sections: []string{".text"}, Corrupt: "section-offset"})
	if _, err := Parse(elfTr, "x"); !IsKind(err, FailureTruncated) {
		t.Fatalf("want truncated, got %v", err)
	}
	// ELF：物理截断 -> truncated
	elfCut, _ := samplegen.ELF64(samplegen.Spec{Sections: []string{".text"}, TruncateAt: 40})
	if _, err := Parse(elfCut, "x"); !IsKind(err, FailureTruncated) {
		t.Fatalf("want truncated for cut elf, got %v", err)
	}

	// ELF：节名字符串表索引越界 -> corrupt（区别于物理截断）
	elfSh, _ := samplegen.ELF64(samplegen.Spec{Sections: []string{".text"}, Corrupt: "shstrndx"})
	if _, err := Parse(elfSh, "x"); !IsKind(err, FailureCorrupt) {
		t.Fatalf("want corrupt for bad shstrndx, got %v", err)
	}
	// PE：签名损坏 -> corrupt
	peSig, _ := samplegen.PE32Plus(samplegen.Spec{Imports: map[string][]string{"a.dll": {"f"}}, Corrupt: "coff-signature"})
	if _, err := Parse(peSig, "x"); !IsKind(err, FailureCorrupt) {
		t.Fatalf("want corrupt, got %v", err)
	}
	// PE：节原始数据越界 -> truncated
	peTr, _ := samplegen.PE32Plus(samplegen.Spec{Imports: map[string][]string{"a.dll": {"f"}}, Corrupt: "section-offset"})
	if _, err := Parse(peTr, "x"); !IsKind(err, FailureTruncated) {
		t.Fatalf("want truncated for pe, got %v", err)
	}
	// PE：导入 RVA 非法 -> corrupt（带可定位 offset）
	peRVA, _ := samplegen.PE32Plus(samplegen.Spec{Imports: map[string][]string{"a.dll": {"f"}}, Corrupt: "rva"})
	perr, err := Parse(peRVA, "x")
	if perr != nil || !IsKind(err, FailureCorrupt) {
		t.Fatalf("want corrupt rva error, got %v", err)
	}
	// PE：物理截断（DOS 头都不完整）
	peCut, _ := samplegen.PE32Plus(samplegen.Spec{Imports: map[string][]string{"a.dll": {"f"}}, TruncateAt: 32})
	if _, err := Parse(peCut, "x"); !IsKind(err, FailureTruncated) {
		t.Fatalf("want truncated for cut pe, got %v", err)
	}
}

func TestParseErrorContext(t *testing.T) {
	b, _ := samplegen.ELF64(samplegen.Spec{Sections: []string{".text"}, Corrupt: "section-offset"})
	_, err := Parse(b, "x")
	pe, ok := err.(*ParseError)
	if !ok {
		t.Fatalf("want *ParseError, got %T", err)
	}
	if pe.Format != FormatELF || pe.Offset < 0 || pe.Context == "" {
		t.Fatalf("error lacks locatable context: %+v", pe)
	}
}
