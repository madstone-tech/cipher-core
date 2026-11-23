package entities

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// MaxOriginalFilenameBytes is the longest original_filename a header can hold.
const MaxOriginalFilenameBytes = 255

// ValidOriginalFilename checks that name is a safe base name for the header
// member original_filename (docs/format-spec.md §Header JSON). The empty
// string means "no name" and is valid.
//
// A safe base name is 1 to 255 bytes of valid UTF-8, is not "." or "..", and
// contains no "/", "\", ":", no C0 or C1 control character (U+0000-U+001F,
// U+007F-U+009F), and no invisible character (invisibleRanges: the Unicode
// 17 Cf, Zl, and Zp characters, bidi controls included). The sender chooses
// this value. Decryptors
// only show it (they never use it as a path), so the rule keeps it from
// naming another directory or drive, and from reordering or controlling a
// terminal when it is shown.
func ValidOriginalFilename(name string) error {
	if name == "" {
		return nil
	}
	if len(name) > MaxOriginalFilenameBytes {
		return fmt.Errorf("original_filename is longer than %d bytes", MaxOriginalFilenameBytes)
	}
	if !utf8.ValidString(name) {
		return fmt.Errorf("original_filename is not valid UTF-8")
	}
	if name == "." || name == ".." {
		return fmt.Errorf("original_filename %q is not a file name", name)
	}
	if strings.ContainsAny(name, `/\:`) {
		return fmt.Errorf("original_filename %q contains a path separator or ':'", name)
	}
	for _, r := range name {
		if isControlOrBidi(r) {
			return fmt.Errorf("original_filename contains a control or bidi character (U+%04X)", r)
		}
	}
	return nil
}

// invisibleRanges lists the Unicode format characters (category Cf) and the
// line and paragraph separators (Zl, Zp) as of Unicode 17: zero-width and
// joiner characters, bidi controls, the BOM, soft hyphen, tag characters, and
// others. The list is explicit (not unicode.Cf) so that the rule does not
// change with a Go or Python Unicode table update (docs/format-spec.md
// §Header JSON).
var invisibleRanges = [][2]rune{
	{0x00AD, 0x00AD},
	{0x0600, 0x0605},
	{0x061C, 0x061C},
	{0x06DD, 0x06DD},
	{0x070F, 0x070F},
	{0x0890, 0x0891},
	{0x08E2, 0x08E2},
	{0x180E, 0x180E},
	{0x200B, 0x200F},
	{0x2028, 0x202E},
	{0x2060, 0x2064},
	{0x2066, 0x206F},
	{0xFEFF, 0xFEFF},
	{0xFFF9, 0xFFFB},
	{0x110BD, 0x110BD},
	{0x110CD, 0x110CD},
	{0x13430, 0x1343F},
	{0x1BCA0, 0x1BCA3},
	{0x1D173, 0x1D17A},
	{0xE0001, 0xE0001},
	{0xE0020, 0xE007F},
}

// isControlOrBidi reports C0/C1 controls and the invisible characters of
// invisibleRanges (bidi controls included).
func isControlOrBidi(r rune) bool {
	if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
		return true
	}
	for _, rg := range invisibleRanges {
		if r >= rg[0] && r <= rg[1] {
			return true
		}
	}
	return false
}
