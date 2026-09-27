package rules_test

import (
	"context"
	"errors"
	"testing"

	"github.com/highcumontoa/binary-analysis-index-go/internal/rules"
)

func TestRegistryCoexistenceAndImmutability(t *testing.T) {
	r := rules.NewRegistry()
	r.MustRegister(rules.BuiltinV1())
	if err := r.Register(rules.BuiltinV1()); err == nil {
		t.Fatal("re-registering a version must fail to keep old results reproducible")
	} else if !errors.Is(err, rules.ErrVersionExists) {
		t.Fatalf("want ErrVersionExists, got %v", err)
	}
	r.MustRegister(rules.BuiltinV2())

	versions := r.Versions()
	if len(versions) != 2 || versions[0] != rules.VersionV1 || versions[1] != rules.VersionV2 {
		t.Fatalf("versions=%v", versions)
	}
	v1, _ := r.Get(rules.VersionV1)
	v2, _ := r.Get(rules.VersionV2)
	if len(v1.Rules()) != 2 || len(v2.Rules()) != 3 {
		t.Fatalf("v1=%d v2=%d rules", len(v1.Rules()), len(v2.Rules()))
	}
}

func TestBuiltinRuleBehavior(t *testing.T) {
	v2 := rules.BuiltinV2()
	ctx := context.Background()
	strippedELF := rules.Facts{Format: "elf", Stripped: true,
		Sections: []rules.Section{{Name: ".note"}}}
	debugELF := rules.Facts{Format: "elf", Stripped: false,
		Sections: []rules.Section{{Name: ".symtab"}}}
	guiPE := rules.Facts{Format: "pe", Subsystem: "gui"}

	eval := func(f rules.Facts) []string {
		var hits []string
		for _, rule := range v2.Rules() {
			m, err := rule.Evaluate(ctx, f)
			if err != nil {
				t.Fatal(err)
			}
			if m != nil {
				hits = append(hits, m.RuleID+":"+string(m.Severity))
			}
		}
		return hits
	}
	if got := eval(strippedELF); len(got) != 2 {
		t.Fatalf("stripped elf hits=%v want classified+elf.stripped", got)
	}
	if got := eval(debugELF); len(got) != 1 || got[0] != "format.classified:info" {
		t.Fatalf("debug elf hits=%v", got)
	}
	if got := eval(guiPE); len(got) != 2 {
		t.Fatalf("gui pe hits=%v want classified+pe-gui", got)
	}
}

func TestFailingRule(t *testing.T) {
	fr := &rules.FailingRule{ID_: "x", Err: errors.New("no")}
	m, err := fr.Evaluate(context.Background(), rules.Facts{})
	if err == nil || m != nil {
		t.Fatalf("m=%v err=%v", m, err)
	}
	if fr.ID() != "x" {
		t.Fatal("id mismatch")
	}
}
