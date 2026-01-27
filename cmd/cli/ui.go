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
	fmt.Printf("[%s %s] > %s\n", nick, timestamp.Format("15:04:05"), text)
	c.rl.Refresh()
}

func (c *ConsoleAdapter) OnFileOffer(peerID string, nick string, filename string, size int64) {
	c.rl.Clean()
	fmt.Printf("\n%s %s предлагает файл: %s (%s)\n", Style.Bell, nick, filename, formatSize(size))
	fmt.Printf("%s Используйте .getfile для принятия или .nofile для отклонения\n\n", Style.Info)
	c.rl.Refresh()
}

func (c *ConsoleAdapter) OnFileProgress(peerID string, nick string, filename string, progress float64, isUpload bool) {
	c.rl.Clean()

	barWidth := 30
	filled := int(progress * float64(barWidth))
	if filled > barWidth {
		filled = barWidth
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)

	direction := "Получение"
	if isUpload {
		direction = "Отправка"
	}

	fmt.Printf("\r%s %s [%s] %.0f%%", direction, filename, bar, progress*100)

	if progress >= 1.0 {
		fmt.Println()
	}
	c.rl.Refresh()
}

func (c *ConsoleAdapter) OnFileReceived(peerID string, nick string, filename string, savedPath string, size int64) {
	c.rl.Clean()
	fmt.Printf("%s Файл от %s сохранён: %s (%s)\n", Style.Mail, nick, savedPath, formatSize(size))
	c.rl.Refresh()
}

func (c *ConsoleAdapter) OnFileComplete(peerID string, nick string, filename string, success bool, message string) {
	c.rl.Clean()
	if success {
		fmt.Printf("%s Передача '%s' завершена: %s\n", Style.OK, filename, message)
	} else {
		fmt.Printf("%s Передача '%s' не удалась: %s\n", Style.Fail, filename, message)
	}
	c.rl.Refresh()
}

func (c *ConsoleAdapter) OnContactUpdate() {
	// В консоли не перерисовываем автоматом
}

func (c *ConsoleAdapter) OnChatChanged(peerID string, nick string) {
	c.rl.Clean()
	if nick != "" {
		c.rl.SetPrompt(fmt.Sprintf("[%s] > ", nick))
		fmt.Printf("\n%s Чат с %s. Forward Secrecy: ON (XChaCha20)\n", Style.Info, nick)
	} else {
		c.rl.SetPrompt("> ")
	}
	c.rl.Refresh()
}

func (c *ConsoleAdapter) DrawBox(title string, lines []string) {
	c.rl.Clean()
	defer c.rl.Refresh()

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

	fmt.Print("\n" + Style.TopLeft)
	fmt.Print(strings.Repeat(Style.Horizontal, contentWidth+2))
	fmt.Println(Style.TopRight)

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

	for _, line := range lines {
		lLen := visibleLen(line)
		rightPadding := contentWidth - lLen

		fmt.Print(Style.Vertical + " ")
		fmt.Print(line)
		fmt.Print(strings.Repeat(" ", rightPadding))
		fmt.Println(" " + Style.Vertical)
	}

	fmt.Print(Style.BottomLeft)
	fmt.Print(strings.Repeat(Style.Horizontal, contentWidth+2))
	fmt.Println(Style.BottomRight)
}

func (c *ConsoleAdapter) PrintBanner() {
	c.DrawBox(fmt.Sprintf("F2F MESSENGER %s", f2f.ProtocolVersion), []string{
		"Forward Secrecy ENABLED (XChaCha20-Poly1305)",
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
		".disconnect [nick]     - разорвать соединение",
		".accept / .decline     - ответ на запрос чата",
		".leave                 - выйти из чата",
		"",
		"--- Файлы ---",
		".file <путь>           - предложить файл",
		".getfile               - принять файл",
		".nofile                - отклонить/отменить файл",
		"",
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

func formatSize(bytes int64) string {
	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
	)
	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.2f GB", float64(bytes)/GB)
	case bytes >= MB:
		return fmt.Sprintf("%.2f MB", float64(bytes)/MB)
	case bytes >= KB:
		return fmt.Sprintf("%.2f KB", float64(bytes)/KB)
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}
