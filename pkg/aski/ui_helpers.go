package f2f

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

func visibleLen(s string) int {
	return utf8.RuneCountInString(s)
}

func SanitizeInput(input string, maxLen int) string {
	runes := []rune(strings.TrimSpace(input))
	safeRunes := make([]rune, 0, len(runes))
	for _, r := range runes {
		if unicode.IsPrint(r) {
			safeRunes = append(safeRunes, r)
		}
	}
	if len(safeRunes) > maxLen {
		return string(safeRunes[:maxLen])
	}
	return string(safeRunes)
}

// isSpoofingRune reports Unicode codepoints commonly abused for filename /
// display spoofing: BIDI overrides (RLO/LRO/RLI/LRI/PDF/PDI), zero-width
// joiners / non-joiners, byte-order marks.
func isSpoofingRune(r rune) bool {
	switch {
	case r >= 0x202A && r <= 0x202E: // LRE, RLE, PDF, LRO, RLO
		return true
	case r >= 0x2066 && r <= 0x2069: // LRI, RLI, FSI, PDI
		return true
	case r == 0x200B || r == 0x200C || r == 0x200D: // ZWSP, ZWNJ, ZWJ
		return true
	case r == 0xFEFF: // BOM / ZWNBSP
		return true
	}
	return false
}

// SanitizeFilename strips BIDI overrides, zero-width chars and non-printable
// characters from a filename. Intended to run AFTER filepath.Base so path
// traversal is already handled.
func SanitizeFilename(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	for _, r := range name {
		if isSpoofingRune(r) {
			continue
		}
		if !unicode.IsPrint(r) {
			continue
		}
		b.WriteRune(r)
	}
	out := b.String()
	if out == "" {
		out = "unnamed"
	}
	return out
}
