package main

import (
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/TheSiriuss/F2F-chat/pkg/f2f"
	"github.com/chzyer/readline"
)

type ConsoleAdapter struct {
	rl *readline.Instance
}

// --- Реализация интерфейса f2f.UIListener ---

func (c *ConsoleAdapter) OnLog(level string, format string, args ...any) {
	c.rl.Clean()
	prefix := ""
	switch level {
	case f2f.LogLevelSuccess:
		prefix = Style.OK + " "
	case f2f.LogLevelError:
		prefix = Style.Fail + " "
	case f2f.LogLevelWarning:
		prefix = Style.Warning + " "
	case f2f.LogLevelInfo:
		prefix = Style.Info + " "
	}
	fmt.Printf(prefix+format+"\n", args...)
	c.rl.Refresh()
}

func (c *ConsoleAdapter) OnMessage(peerID string, nick string, text string, timestamp time.Time) {
	c.rl.Clean()
	fmt.Printf("\n%s [%s %s]: %s\n", Style.Mail, nick, timestamp.Format("15:04"), text)
	c.rl.Refresh()
}

func (c *ConsoleAdapter) OnContactUpdate() {
	// В консоли мы не перерисовываем список автоматом, чтобы не мусорить
}

func (c *ConsoleAdapter) OnChatChanged(peerID string, nick string) {
	if nick != "" {
		c.rl.SetPrompt(fmt.Sprintf("[%s] > ", nick))
	} else {
		c.rl.SetPrompt("> ")
	}
	c.rl.Refresh()
}

// --- Вспомогательные функции отрисовки (вернули из старого проекта) ---

func (c *ConsoleAdapter) DrawBox(title string, lines []string) {
	c.rl.Clean()
	defer c.rl.Refresh()

	// Вычисляем ширину
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

	// Верхняя рамка
	fmt.Print("\n" + Style.TopLeft)
	fmt.Print(strings.Repeat(Style.Horizontal, contentWidth+2))
	fmt.Println(Style.TopRight)

	// Заголовок
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

	// Контент
	for _, line := range lines {
		lLen := visibleLen(line)
		rightPadding := contentWidth - lLen

		fmt.Print(Style.Vertical + " ")
		fmt.Print(line)
		fmt.Print(strings.Repeat(" ", rightPadding))
		fmt.Println(" " + Style.Vertical)
	}

	// Нижняя рамка
	fmt.Print(Style.BottomLeft)
	fmt.Print(strings.Repeat(Style.Horizontal, contentWidth+2))
	fmt.Println(Style.BottomRight)
}

func (c *ConsoleAdapter) PrintBanner() {
	c.DrawBox(fmt.Sprintf("F2F MESSENGER %s", f2f.ProtocolVersion), []string{
		"Forward Secrecy ENABLED",
		".help - справка | Ctrl+C - выход",
	})
}

func (c *ConsoleAdapter) PrintHelp() {
	c.DrawBox("КОМАНДЫ", []string{
		".login <nick>          - создать/войти в профиль",
		".logout                - выйти из профиля",
		".bootstrap             - подключиться к DHT",
		".info                  - мои данные",
		".fingerprint           - fingerprint ключа",
		".addfriend <n> <p> <k> - добавить контакт",
		".removefriend <nick>   - удалить контакт",
		".connect <nick>        - начать чат",
		".disconnect [nick]     - отменить/разорвать соединение",
		".accept / .decline     - ответ на запрос",
		".leave                 - выйти из чата",
		".list                  - контакты",
		".check                 - обновить статусы",
		".find <nick>           - найти в DHT",
		".exit или Ctrl+C       - выход",
	})
}

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
