package main

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// visibleLen returns visible character count (not bytes)
func visibleLen(s string) int {
	return utf8.RuneCountInString(s)
}

// SanitizeInput removes non-printable characters and limits length
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

// updatePrompt updates readline prompt based on active chat
func (n *Node) updatePrompt() {
	if !n.useReadline || n.rl == nil {
		return
	}

	n.mu.RLock()
	activeID := n.activeChat
	var activeNick string
	if activeID != "" {
		if c, ok := n.contacts[activeID]; ok {
			activeNick = c.Nickname
		}
	}
	n.mu.RUnlock()

	if activeNick != "" {
		n.rl.SetPrompt(fmt.Sprintf("[%s] > ", activeNick))
	} else {
		n.rl.SetPrompt("> ")
	}
}

// printPrompt prints prompt for non-readline mode
func (n *Node) printPrompt() {
	n.mu.RLock()
	activeID := n.activeChat
	var activeNick string
	if activeID != "" {
		if c, ok := n.contacts[activeID]; ok {
			activeNick = c.Nickname
		}
	}
	n.mu.RUnlock()

	if activeNick != "" {
		fmt.Printf("[%s] > ", activeNick)
	} else {
		fmt.Print("> ")
	}
}

// drawBox draws a box with title and content
func (n *Node) drawBox(title string, lines []string) {
	n.uiMu.Lock()
	defer n.uiMu.Unlock()

	if n.useReadline && n.rl != nil {
		n.rl.Clean()
	}

	// Calculate width
	contentWidth := 0
	if title != "" {
		contentWidth = visibleLen(title)
	}
	for _, line := range lines {
		l := visibleLen(line)
		if l > contentWidth {
			contentWidth = l
		}
	}
	if contentWidth < 40 {
		contentWidth = 40
	}

	// Top border
	fmt.Print("\n" + Style.TopLeft)
	fmt.Print(strings.Repeat(Style.Horizontal, contentWidth+2))
	fmt.Println(Style.TopRight)

	// Title
	if title != "" {
		tLen := visibleLen(title)
		padding := (contentWidth - tLen) / 2
		rightPadding := contentWidth - tLen - padding

		fmt.Print(Style.Vertical + " ")
		fmt.Print(strings.Repeat(" ", padding))
		fmt.Print(title)
		fmt.Print(strings.Repeat(" ", rightPadding))
		fmt.Println(" " + Style.Vertical)

		fmt.Print(Style.TeeLeft)
		fmt.Print(strings.Repeat(Style.Horizontal, contentWidth+2))
		fmt.Println(Style.TeeRight)
	}

	// Content
	for _, line := range lines {
		lLen := visibleLen(line)
		rightPadding := contentWidth - lLen

		fmt.Print(Style.Vertical + " ")
		fmt.Print(line)
		fmt.Print(strings.Repeat(" ", rightPadding))
		fmt.Println(" " + Style.Vertical)
	}

	// Bottom border
	fmt.Print(Style.BottomLeft)
	fmt.Print(strings.Repeat(Style.Horizontal, contentWidth+2))
	fmt.Println(Style.BottomRight)

	if n.useReadline && n.rl != nil {
		n.rl.Refresh()
	}
}

// printBanner prints welcome banner
func (n *Node) printBanner() {
	n.drawBox(fmt.Sprintf("F2F MESSENGER %s", ProtocolVersion), []string{
		"Forward Secrecy ENABLED",
		".help - справка | Ctrl+C - выход",
	})
}

// printHelp prints help message
func (n *Node) printHelp() {
	n.drawBox("КОМАНДЫ", []string{
		".login <nick>          - создать профиль",
		".logout                - сбросить профиль",
		".bootstrap             - подключиться к DHT",
		".info                  - мои данные",
		".fingerprint [nick]    - fingerprint ключа",
		".addfriend <n> <p> <k> - добавить контакт",
		".connect <nick>        - начать чат",
		".accept / .decline     - ответ на запрос",
		".leave                 - выйти из чата",
		".list                  - контакты",
		".check                 - обновить статусы",
		".find <nick>           - найти в DHT",
		".exit или Ctrl+C       - выход",
	})
}

// SafePrintf thread-safe printf with readline refresh
func (n *Node) SafePrintf(format string, a ...any) {
	n.uiMu.Lock()
	defer n.uiMu.Unlock()

	if n.useReadline && n.rl != nil {
		n.rl.Clean()
	}

	fmt.Printf(format, a...)

	if n.useReadline && n.rl != nil {
		n.rl.Refresh()
	}
}
