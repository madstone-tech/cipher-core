package entities

import (
	"testing"
	"unicode"
)

// TestInvisibleRangesMatchUnicode guards the frozen list: for the Unicode
// version of this Go toolchain, invisibleRanges is exactly Cf ∪ Zl ∪ Zp. A
// failure after a Go update means Unicode added a format character: decide
// in a spec change whether the frozen list grows (it changes the format rule).
func TestInvisibleRangesMatchUnicode(t *testing.T) {
	for r := rune(0); r <= unicode.MaxRune; r++ {
		want := unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp)
		got := false
		for _, rg := range invisibleRanges {
			if r >= rg[0] && r <= rg[1] {
				got = true
			}
		}
		if got != want {
			t.Fatalf("U+%04X: in list = %v, in Cf/Zl/Zp = %v (Unicode %s)", r, got, want, unicode.Version)
		}
	}
}
