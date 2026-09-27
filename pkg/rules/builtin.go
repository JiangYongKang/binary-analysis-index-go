package rules

import (
	"context"
	"fmt"
	"strings"

	"github.com/highcumontoa/binary-analysis-index-go/pkg/binfmt"
)

// 内置版本号（语义化版本）。新版本只增不改；v2 的规则与 v1 行为不同，
// 因此同一个样本在两个版本下的结论都保留、都可复现。
const (
	Version1 = "1.0.0"
	Version2 = "2.0.0"
)

// BuiltinVersions 返回内置规则版本，按从旧到新排序。
func BuiltinVersions() []string { return []string{Version1, Version2} }

// BuiltinEngine 返回指定内置版本的引擎；未知版本返回错误（不允许静默回退到其它版本）。
func BuiltinEngine(version string) (*Engine, error) {
	switch version {
	case Version1:
		return NewEngine(Version1, v1Rules()), nil
	case Version2:
		return NewEngine(Version2, v2Rules()), nil
	default:
		return nil, fmt.Errorf("unknown builtin rule version %q (known: %v)", version, BuiltinVersions())
	}
}

// ---- 具体规则 -------------------------------------------------------------

// upxPackedRule：检测 UPX 风格加壳节（高熵 + 名称特征）。
type upxPackedRule struct {
	id     string
	sev    Severity
	minEnt float64
}

func (r *upxPackedRule) ID() string         { return r.id }
func (r *upxPackedRule) Severity() Severity { return r.sev }

func (r *upxPackedRule) Eval(_ context.Context, info *binfmt.BinaryInfo) (bool, string, string, error) {
	var hits []string
	for _, s := range info.Sections {
		if s.IsUPXLike && s.Entropy >= r.minEnt {
			hits = append(hits, fmt.Sprintf("%s(entropy=%.2f,size=%d)", s.Name, s.Entropy, s.Size))
		}
	}
	if len(hits) == 0 {
		return false, "", "", nil
	}
	return true,
		"packed (UPX-like) section detected",
		fmt.Sprintf("sections with UPX-style name and entropy>=%.1f: %s", r.minEnt, strings.Join(hits, "; ")), nil
}

// peImportRule：要求 PE 至少导入一组安全 API；v1 只看集合是否出现，v2 精确到单个 API。
type peImportRule struct {
	id    string
	sev   Severity
	exact bool // true(v2)：API 必须逐个出现；false(v1)：命中任一即可
	need  map[string][]string
}

func (r *peImportRule) ID() string         { return r.id }
func (r *peImportRule) Severity() Severity { return r.sev }

func lower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

func (r *peImportRule) Eval(_ context.Context, info *binfmt.BinaryInfo) (bool, string, string, error) {
	if info.Format != binfmt.FormatPE {
		return false, "", "", nil
	}
	have := map[string]bool{}
	for dll, syms := range info.Imports {
		for _, s := range syms {
			have[lower(dll)+"!"+lower(s)] = true
		}
	}
	type missingAPI = struct{ dll, api string }
	var missing []missingAPI
	var satisfiedAny bool
	for dll, apis := range r.need {
		for _, api := range apis {
			if have[lower(dll)+"!"+lower(api)] {
				satisfiedAny = true
				continue
			}
			missing = append(missing, missingAPI{dll, api})
		}
	}
	// v1 宽口径：只要导入集合里出现任意一个安全 API 即视为正常；全缺才告警。
	// v2 严口径：每个要求的 API 都必须存在。
	hit := false
	var why string
	if !r.exact {
		if !satisfiedAny {
			hit = true
			why = "PE imports none of the expected safe APIs: " + joinMiss(missing)
		}
	} else {
		if len(missing) > 0 {
			hit = true
			why = "PE is missing required imports: " + joinMiss(missing)
		}
	}
	if hit {
		return true, "PE missing expected import surface", why, nil
	}
	return false, "", "", nil
}

func joinMiss(ms []struct{ dll, api string }) string {
	parts := make([]string, len(ms))
	for i, m := range ms {
		parts[i] = m.dll + "!" + m.api
	}
	sortStrings(parts)
	return strings.Join(parts, ", ")
}

// dotNetRule（v2 新增）：PE 存在 CLR 数据目录时这里无法深入元数据，
// 通过节名 ".text" + 导入 mscoree.dll!_CorDllMain/_CorExeMain 的常见特征近似标记，
// 仅作 info 级提示，演示“新版本新增规则”。
type dotNetRule struct{}

func (dotNetRule) ID() string         { return "PE_DOTNET_002" }
func (dotNetRule) Severity() Severity { return SeverityInfo }
func (dotNetRule) Eval(_ context.Context, info *binfmt.BinaryInfo) (bool, string, string, error) {
	if info.Format != binfmt.FormatPE {
		return false, "", "", nil
	}
	for _, s := range info.Sections {
		if lower(s.Name) == ".rsrc" {
			// .rsrc 存在仅作为演示辅助，不直接命中
		}
	}
	for dll, syms := range info.Imports {
		for _, s := range syms {
			if lower(dll) == "mscoree.dll" && strings.HasPrefix(lower(s), "_cor") {
				return true, "managed (.NET) assembly bootstrap import detected",
					fmt.Sprintf("import %s!%s indicates CLR bootstrapping", dll, s), nil
			}
		}
	}
	return false, "", "", nil
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

// v1Rules：初版规则集（宽口径导入检查）。
func v1Rules() []Rule {
	return []Rule{
		&upxPackedRule{id: "PACKED_001", sev: SeverityHigh, minEnt: 6.5},
		&peImportRule{
			id:    "PE_IMPORTS_001",
			sev:   SeverityMedium,
			exact: false,
			need: map[string][]string{
				"KERNEL32.dll": {"CreateFileW"},
			},
		},
	}
}

// v2Rules：规则升级。
//   - PACKED_001 阈值收紧（6.5 -> 7.0）；
//   - PE_IMPORTS_002 改为逐个 API 的严口径检查；
//   - 新增 PE_DOTNET_002。
func v2Rules() []Rule {
	return []Rule{
		&upxPackedRule{id: "PACKED_001", sev: SeverityHigh, minEnt: 7.0},
		&peImportRule{
			id:    "PE_IMPORTS_002",
			sev:   SeverityHigh,
			exact: true,
			need: map[string][]string{
				"KERNEL32.dll": {"CreateFileW", "WriteFile"},
			},
		},
		dotNetRule{},
	}
}
