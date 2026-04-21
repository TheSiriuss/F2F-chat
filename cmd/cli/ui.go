package main

import (
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/TheSiriuss/aski/pkg/aski"
	"github.com/chzyer/readline"
)

type ConsoleAdapter struct {
	rl     *readline.Instance
	selfID string // set once after NewNode() — our own libp2p PeerID as string

	// Incoming ASCII video: height of the most recently-rendered frame so
	// we can erase that many lines before drawing the next one (in-place).
	lastVideoHeight int
}

// SetSelfID records our own host ID so OnMessage can distinguish our own
// echoed messages from incoming ones (self-echo needs extra cursor cleanup).
func (c *ConsoleAdapter) SetSelfID(id string) {
	c.selfID = id
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
	if c.selfID != "" && peerID == c.selfID {
		// Self-echo path: after Enter, readline committed the typed line to
		// the scrollback (e.g. "[bob] > 1"). We do the cursor moves OURSELVES
		// without calling rl.Clean first — Clean's internal state tracking
		// conflicts with raw cursor manipulation on some Windows terminals.
		//
		// \x1b[F — Cursor Previous Line (CPL): moves cursor up one line
		//          AND to column 0 atomically. Much more reliable than the
		//          \x1b[1A + \r combo across terminals.
		// \x1b[2K — Erase in Line (EL): clears the whole current line.
		fmt.Print("\x1b[F\x1b[2K")
		fmt.Printf("[%s %s] > %s\n", nick, timestamp.Format("15:04:05"), text)
		c.rl.Refresh()
		return
	}
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
	if f2f.IsVoiceMessage(filename) {
		fmt.Printf("%s Голосовое от %s: %s (%s) — .play %s\n", Style.Mail, nick, savedPath, formatSize(size), savedPath)
		settings := f2f.LoadSettings()
		if settings.VoiceAutoPlay {
			fmt.Printf("> автовоспроизведение…\n")
			go func() {
				_ = f2f.PlayWAV(settings.AudioOutputDeviceID, savedPath)
			}()
		}
	} else {
		fmt.Printf("%s Файл от %s сохранён: %s (%s)\n", Style.Mail, nick, savedPath, formatSize(size))
	}
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

// OnVideoFrame renders one ASCII frame in-place: the previous frame is
// erased line-by-line, then the new one is printed, and the readline prompt
// is refreshed below. The first frame prints a header line so the user
// knows what they're looking at.
func (c *ConsoleAdapter) OnVideoFrame(peerID, nick, frame string) {
	c.rl.Clean()

	// Erase previous frame's lines (including the header line we printed).
	if c.lastVideoHeight > 0 {
		for i := 0; i < c.lastVideoHeight; i++ {
			fmt.Print("\x1b[1A\x1b[2K")
		}
	}

	header := fmt.Sprintf("[video] Видео от %s (%s):", nick, Style.Info)
	fmt.Println(header)
	fmt.Println(frame)

	// Count header (1) + frame lines (newlines + 1).
	frameLines := strings.Count(frame, "\n") + 1
	c.lastVideoHeight = 1 + frameLines

	c.rl.Refresh()
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
		// Center each body line so the box looks balanced on startup.
		leftPadding := (contentWidth - lLen) / 2
		rightPadding := contentWidth - lLen - leftPadding

		fmt.Print(Style.Vertical + " ")
		fmt.Print(strings.Repeat(" ", leftPadding))
		fmt.Print(line)
		fmt.Print(strings.Repeat(" ", rightPadding))
		fmt.Println(" " + Style.Vertical)
	}

	fmt.Print(Style.BottomLeft)
	fmt.Print(strings.Repeat(Style.Horizontal, contentWidth+2))
	fmt.Println(Style.BottomRight)
}

func (c *ConsoleAdapter) PrintBanner() {
	c.DrawBox("ASKI CHAT main 1.0", []string{
		"Decentralised P2P messenger",
		"Double Ratchet + XChaCha20-Poly1305",
		"",
		".help — help  |  Ctrl+C — quit",
	})
}

func (c *ConsoleAdapter) PrintHelp() {
	c.DrawBox("КОМАНДЫ", []string{
		"--- Профиль ---",
		".login <nick>          - создать/войти в профиль",
		".logout                - выйти из профиля",
		".info                  - мои данные",
		".fingerprint           - fingerprint ключа (160 бит)",
		"",
		"--- Контакты ---",
		".addfriend <n> <p> <k> - добавить контакт",
		".removefriend <nick>   - удалить контакт",
		".list                  - контакты со статусами",
		".check                 - обновить статусы",
		".find <nick>           - найти в DHT",
		"",
		"--- Чат ---",
		".connect <nick>        - начать чат",
		".disconnect [nick]     - разорвать соединение",
		".accept <nick>         - принять запрос чата",
		".decline <nick>        - отклонить запрос чата",
		".leave                 - выйти из чата",
		"",
		"--- Файлы ---",
		".file <путь>           - предложить файл",
		".getfile               - принять файл",
		".nofile                - отклонить/отменить файл",
		"",
		"--- Голосовые сообщения ---",
		".rec [сек]             - записать (Enter — стоп)",
		".play <путь>           - проиграть wav в консоли",
		"",
		"--- Звонки ---",
		".voicecall [nick]      - позвонить голосом",
		".videocall [nick]      - позвонить с видео (голос + ASCII)",
		".acceptcall [nick]     - принять входящий вызов",
		".declinecall [nick]    - отклонить вызов",
		".hangup [nick]         - завершить вызов",
		".video [src]           - включить видео в активном вызове",
		"                         (src: camera/file/<путь>)",
		".stopvideo             - выключить видео",
		"",
		"--- Настройка ---",
		".settings              - микрофон/аудиовыход/камера/источник",
		".cameras               - список камер (диагностика)",
		".ffmpeg [install]      - статус / скачать ffmpeg для камеры",
		"",
		"--- Сеть ---",
		".bootstrap             - подключиться к DHT",
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
