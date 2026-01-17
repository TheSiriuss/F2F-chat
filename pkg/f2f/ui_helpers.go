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
