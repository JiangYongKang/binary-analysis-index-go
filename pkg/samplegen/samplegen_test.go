package samplegen

import (
	"bytes"
	"testing"
)

func TestGeneratorsDeterministic(t *testing.T) {
	a1, _ := ELF64(Spec{Sections: []string{".text", "UPX0"}})
	a2, _ := ELF64(Spec{Sections: []string{".text", "UPX0"}})
	if !bytes.Equal(a1, a2) {
		t.Fatal("ELF generator not deterministic")
	}
	p1, _ := PE32Plus(Spec{Sections: []string{".rsrc"}, Imports: map[string][]string{"B.dll": {"y"}, "A.dll": {"x"}}})
	p2, _ := PE32Plus(Spec{Sections: []string{".rsrc"}, Imports: map[string][]string{"A.dll": {"x"}, "B.dll": {"y"}}})
	if !bytes.Equal(p1, p2) {
		t.Fatal("PE generator must be independent of Go map iteration order")
	}
	if len(p1)%0x200 != 0 {
		t.Fatalf("PE size not file-aligned: %d", len(p1))
	}
}

func TestTruncationActuallyShortens(t *testing.T) {
	full, _ := ELF64(Spec{Sections: []string{".text"}})
	cut, _ := ELF64(Spec{Sections: []string{".text"}, TruncateAt: 20})
	if len(cut) != 20 || len(cut) >= len(full) {
		t.Fatalf("truncation failed: full=%d cut=%d", len(full), len(cut))
	}
}

func TestRandomBytesHighEntropy(t *testing.T) {
	if bytes.Equal(RandomBytes(32), RandomBytes(32)) == false {
		// 固定种子：两次必须一致
		t.Fatal("RandomBytes not reproducible (fixed seed expected)")
	}
	b := RandomBytes(1024)
	seen := map[byte]int{}
	for _, c := range b {
		seen[c]++
	}
	if len(seen) < 200 {
		t.Fatalf("supposedly random data has only %d distinct byte values", len(seen))
	}
}
