package rules

import (
	"context"
	"errors"
	"testing"

	"github.com/highcumontoa/binary-analysis-index-go/pkg/binfmt"
	"github.com/highcumontoa/binary-analysis-index-go/pkg/samplegen"
)

func parse(t *testing.T, data []byte) *binfmt.BinaryInfo {
	t.Helper()
	info, err := binfmt.Parse(data, "x")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return info
}

func TestV1AndV2CoexistAndDiffer(t *testing.T) {
	ctx := context.Background()
	// 样本：UPX 节熵约 7.8；只导入 CreateFileW（缺 WriteFile）。
	pe, err := samplegen.PE32Plus(samplegen.Spec{
		Imports: map[string][]string{"KERNEL32.dll": {"CreateFileW"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	info := parse(t, pe)

	v1, err := BuiltinEngine(Version1)
	if err != nil {
		t.Fatal(err)
	}
	v2, err := BuiltinEngine(Version2)
	if err != nil {
		t.Fatal(err)
	}
	m1, verdict1, basis1, err := v1.Analyze(ctx, info)
	if err != nil {
		t.Fatal(err)
	}
	m2, verdict2, basis2, err := v2.Analyze(ctx, info)
	if err != nil {
		t.Fatal(err)
	}
	// v1 宽口径：CreateFileW 已满足 -> 不命中 PE_IMPORTS_001
	if verdict1 != VerdictClean || len(m1) != 0 {
		t.Fatalf("v1 expected clean, got %s matches=%v basis=%s", verdict1, m1, basis1)
	}
	// v2 严口径：缺 WriteFile -> 命中 PE_IMPORTS_002
	if verdict2 != VerdictSuspicious {
		t.Fatalf("v2 expected suspicious, got %s basis=%s", verdict2, basis2)
	}
	found := false
	for _, m := range m2 {
		if m.RuleID == "PE_IMPORTS_002" && m.Severity == SeverityHigh && m.Basis != "" {
			found = true
		}
	}
	if !found {
		t.Fatalf("v2 matches missing PE_IMPORTS_002: %+v", m2)
	}
}

func TestUPXRuleVersionThreshold(t *testing.T) {
	elf, err := samplegen.ELF64(samplegen.Spec{Sections: []string{".text", "UPX0"}})
	if err != nil {
		t.Fatal(err)
	}
	info := parse(t, elf)
	for _, v := range BuiltinVersions() {
		eng, _ := BuiltinEngine(v)
		ms, verdict, basis, err := eng.Analyze(context.Background(), info)
		if err != nil {
			t.Fatal(err)
		}
		if verdict != VerdictSuspicious || len(ms) != 1 || ms[0].RuleID != "PACKED_001" {
			t.Fatalf("version %s expected single PACKED_001 hit, got %v (%s)", v, ms, basis)
		}
	}
}

func TestRuleExecutionFailureIsExplicit(t *testing.T) {
	eng := NewEngine("test-broken", []Rule{boomRule{}})
	_, _, _, err := eng.Analyze(context.Background(), &binfmt.BinaryInfo{Format: binfmt.FormatELF})
	var re *RuleError
	if !errors.As(err, &re) {
		t.Fatalf("want *RuleError, got %v", err)
	}
	if re.RuleID != "BOOM_001" || re.Version != "test-broken" {
		t.Fatalf("rule error context lost: %+v", re)
	}
	// 规则错误不得被当作“未命中/clean”——Index 层会据此写 StatusFailed。
}

type boomRule struct{}

func (boomRule) ID() string         { return "BOOM_001" }
func (boomRule) Severity() Severity { return SeverityHigh }
func (boomRule) Eval(context.Context, *binfmt.BinaryInfo) (bool, string, string, error) {
	return false, "", "", errors.New("simulated rule engine crash")
}

func TestUnknownVersionRejected(t *testing.T) {
	if _, err := BuiltinEngine("9.9.9"); err == nil {
		t.Fatal("unknown version must be rejected, not silently mapped")
	}
}

func TestCleanBasis(t *testing.T) {
	pe, _ := samplegen.PE32Plus(samplegen.Spec{
		Imports: map[string][]string{"KERNEL32.dll": {"CreateFileW", "WriteFile"}},
	})
	info := parse(t, pe)
	eng, _ := BuiltinEngine(Version2)
	ms, verdict, basis, err := eng.Analyze(context.Background(), info)
	if err != nil {
		t.Fatal(err)
	}
	if verdict != VerdictClean || len(ms) != 0 || basis == "" {
		t.Fatalf("expected clean with non-empty basis, got %s %v %q", verdict, ms, basis)
	}
}
