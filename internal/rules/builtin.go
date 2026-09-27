package rules

import (
	"context"
	"fmt"
)

// VersionV1 and VersionV2 identify the built-in rule sets.
const (
	VersionV1 = "builtin-2026.1"
	VersionV2 = "builtin-2026.2"
)

// FailingRule always returns the given error; it exists to exercise the
// "rule execution failure" path deterministically in tests.
type FailingRule struct {
	ID_ string
	Err error
}

func (r *FailingRule) ID() string { return r.ID_ }

func (r *FailingRule) Evaluate(ctx context.Context, f Facts) (*Match, error) {
	return nil, fmt.Errorf("rule %q failed: %w", r.ID_, r.Err)
}

// BuiltinV1 returns the first stable rule set.
//
// Rules:
//   - format.classified (info) sample recognised as ELF or PE;
//   - format.pe-gui     (info) PE GUI subsystem.
//
// With only info-severity matches, every successfully parsed sample is
// "clean" under v1.
func BuiltinV1() *Set {
	return NewSet(VersionV1,
		&BasicRule{
			ID_: "format.classified", Sev: SeverityInfo,
			Msg: "sample format recognised",
			Check: func(ctx context.Context, f Facts) (bool, error) {
				return f.Format == "elf" || f.Format == "pe", nil
			},
		},
		&BasicRule{
			ID_: "format.pe-gui", Sev: SeverityInfo,
			Msg: "PE subsystem is GUI",
			Check: func(ctx context.Context, f Facts) (bool, error) {
				return f.Format == "pe" && f.Subsystem == "gui", nil
			},
		},
	)
}

// BuiltinV2 returns the successor rule set. Old v1 results remain
// reproducible because v1 stays registered alongside v2.
//
// Added rules:
//   - elf.stripped (warning) ELF with no .symtab section.
//
// The new warning means a stripped ELF is "suspicious" under v2 while it was
// "clean" under v1; both verdicts remain queryable.
func BuiltinV2() *Set {
	return NewSet(VersionV2,
		&BasicRule{
			ID_: "format.classified", Sev: SeverityInfo,
			Msg: "sample format recognised",
			Check: func(ctx context.Context, f Facts) (bool, error) {
				return f.Format == "elf" || f.Format == "pe", nil
			},
		},
		&BasicRule{
			ID_: "format.pe-gui", Sev: SeverityInfo,
			Msg: "PE subsystem is GUI",
			Check: func(ctx context.Context, f Facts) (bool, error) {
				return f.Format == "pe" && f.Subsystem == "gui", nil
			},
		},
		&BasicRule{
			ID_: "elf.stripped", Sev: SeverityWarning,
			Msg: "ELF has no .symtab section (stripped)",
			Check: func(ctx context.Context, f Facts) (bool, error) {
				return f.Format == "elf" && f.Stripped, nil
			},
		},
	)
}
