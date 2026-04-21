package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"runtime"
	"strings"
	"unicode"

	"github.com/TheSiriuss/aski/cmd/cli/tui"
	"github.com/TheSiriuss/aski/pkg/aski"
	"github.com/chzyer/readline"
	"golang.org/x/term"
)

func main() {
	initStyle()
	enableANSI()

	rl, err := readline.NewEx(&readline.Config{
		Prompt:          "> ",
		InterruptPrompt: "^C",
		EOFPrompt:       ".exit",
	})
	if err != nil {
		panic(err)
	}
	defer func() { _ = rl.Close() }()

	// Turn on ANSI/VT processing for stdout on Windows so our cursor
	// manipulation escapes (\x1b[F, \x1b[2K etc.) actually take effect.
	enableVTMode()

	bootstrapUI := &ConsoleAdapter{rl: rl}

	fmt.Print("\033[H\033[2J")
	bootstrapUI.PrintBanner()

	password, err := getPassword(bootstrapUI)
	if err != nil {
		fmt.Println("Ошибка:", err)
		return
	}

	// TUI adapter — receives all f2f events and forwards them to bubbletea.
	// Events that fire before tui.Run() attaches a program are dropped, so
	// we show a "starting..." line and kick things off quickly.
	fmt.Println("\nЗагрузка F2F...")

	tuiAdapter := tui.NewAdapter()

	ctx := context.Background()
	node, err := f2f.NewNode(ctx, tuiAdapter, password)
	if err != nil {
		if err == f2f.ErrWrongPassword {
			fmt.Println("Неверный пароль!")
		} else {
			fmt.Println("Critical Error:", err)
		}
		return
	}

	if err := node.LoadContacts(); err != nil {
		// Silent fail
		_ = err
	}

	// Hand control to bubbletea. Blocks until Ctrl+C / /quit.
	if err := tui.Run(node, tuiAdapter); err != nil {
		fmt.Println("TUI error:", err)
	}

	node.Shutdown()
}

// Legacy readline REPL — replaced by the bubbletea TUI in cmd/cli/tui.
// Kept out of the build; reference only.
func legacyREPL(rl *readline.Instance, node *f2f.Node, ui *ConsoleAdapter) {
	for {
		line, err := rl.Readline()
		if err != nil {
			break
		}

		if !strings.HasPrefix(line, ".") {
			active := node.GetActiveChat()
			if active.String() != "" {
				cleanMsg := SanitizeInput(line, f2f.MaxMsgLength)
				if cleanMsg != "" {
					node.SendChatMessage(active, cleanMsg)
				}
			} else {
				if strings.TrimSpace(line) != "" {
					ui.OnLog(f2f.LogLevelWarning, "Вы не в чате. Используйте команды или .connect")
				}
			}
			continue
		}

		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		cmd := strings.ToLower(parts[0])

		switch cmd {
		case ".login":
			if len(parts) > 1 {
				cleanNick := SanitizeInput(parts[1], 32)
				node.Login(cleanNick)
				printNodeInfo(ui, node)
			} else {
				ui.OnLog(f2f.LogLevelInfo, "Использование: .login <ник>")
			}
		case ".logout":
			node.Logout()

		case ".removefriend", ".remove", ".unfriend":
			if len(parts) > 1 {
				node.RemoveFriend(parts[1])
			} else {
				ui.OnLog(f2f.LogLevelInfo, "Использование: .removefriend <nick>")
			}

		case ".bootstrap":
			go node.ConnectToBootstrap()

		case ".info":
			printNodeInfo(ui, node)

		case ".qr":
			qr, err := node.GenerateInviteQR()
			if err != nil {
				ui.OnLog(f2f.LogLevelError, "QR: %v", err)
			} else {
				ui.OnLog(f2f.LogLevelInfo, "QR-код приглашения (сканируйте или покажите другу):")
				fmt.Println(qr)
			}

		case ".sas":
			if len(parts) < 2 {
				ui.OnLog(f2f.LogLevelInfo, "Использование: .sas <nick>")
				break
			}
			code := node.GetSASCode(parts[1])
			if code == "" {
				ui.OnLog(f2f.LogLevelWarning, "Нет активной сессии с %s", parts[1])
			} else {
				ui.DrawBox("SAS ДЛЯ "+parts[1], []string{
					code,
					"",
					"Прочитайте код собеседнику по голосовому каналу.",
					"Если коды совпадают — MITM исключён.",
				})
			}

		case ".fingerprint":
			if len(parts) > 1 {
				ui.OnLog(f2f.LogLevelInfo, "Пока работает только для своего ключа (без аргументов)")
			} else {
				idStr := node.GetIdentityString()
				idParts := strings.Fields(idStr)
				if len(idParts) >= 4 {
					pubKeyBytes, _ := base64.StdEncoding.DecodeString(idParts[3])
					fp := f2f.ComputeFingerprint(pubKeyBytes)
					ui.DrawBox("ВАШ FINGERPRINT", []string{fp})
				} else {
					ui.OnLog(f2f.LogLevelWarning, "Сначала залогиньтесь")
				}
			}

		case ".addfriend", ".add":
			if len(parts) >= 4 {
				node.AddFriend(parts[1], parts[2], parts[3])
			} else {
				ui.OnLog(f2f.LogLevelInfo, "Использование: .addfriend <nick> <peerID> <pubkey>")
			}

		case ".connect":
			if len(parts) > 1 {
				go node.InitConnect(parts[1])
			} else {
				ui.OnLog(f2f.LogLevelInfo, "Использование: .connect <nick>")
			}

		case ".disconnect":
			if len(parts) > 1 {
				node.Disconnect(parts[1])
			} else {
				active := node.GetActiveChat()
				if active.String() != "" {
					node.DisconnectByPeerID(active)
				} else {
					ui.OnLog(f2f.LogLevelInfo, "Использование: .disconnect <nick> или .disconnect (в активном чате)")
				}
			}

		case ".accept":
			if len(parts) > 1 {
				node.HandleDecision(parts[1], true)
			} else {
				ui.OnLog(f2f.LogLevelInfo, "Использование: .accept <nick>")
			}

		case ".decline":
			if len(parts) > 1 {
				node.HandleDecision(parts[1], false)
			} else {
				ui.OnLog(f2f.LogLevelInfo, "Использование: .decline <nick>")
			}

		case ".leave":
			node.LeaveChat()

		case ".file":
			if len(parts) > 1 {
				active := node.GetActiveChat()
				if active.String() == "" {
					ui.OnLog(f2f.LogLevelWarning, "Вы не в чате. Сначала подключитесь к контакту")
					break
				}
				filePath := strings.Join(parts[1:], " ")
				if err := node.SendFile(active, filePath); err != nil {
					ui.OnLog(f2f.LogLevelError, "Ошибка: %v", err)
				}
			} else {
				ui.OnLog(f2f.LogLevelInfo, "Использование: .file <путь к файлу>")
			}

		case ".getfile":
			active := node.GetActiveChat()
			if active.String() == "" {
				ui.OnLog(f2f.LogLevelWarning, "Вы не в чате")
				break
			}
			if err := node.AcceptFile(""); err != nil {
				ui.OnLog(f2f.LogLevelError, "Ошибка: %v", err)
			}

		case ".nofile":
			active := node.GetActiveChat()
			if active.String() == "" {
				ui.OnLog(f2f.LogLevelWarning, "Вы не в чате")
				break
			}
			if err := node.DeclineFile(""); err != nil {
				ui.OnLog(f2f.LogLevelError, "Ошибка: %v", err)
			}

		case ".list":
			contacts := node.GetContacts()
			var lines []string
			if len(contacts) == 0 {
				lines = append(lines, "(пусто)")
			}
			for _, c := range contacts {
				icon := Style.Offline
				status := "OFFLINE"
				if c.Stream != nil {
					icon = Style.Connected
					status = "CONNECTED"
				} else if c.State == f2f.StateActive {
					icon = Style.InChat
					status = "IN CHAT"
				} else if c.State == f2f.StatePendingOutgoing {
					icon = Style.Pending
					status = "CONNECTING..."
				} else if c.State == f2f.StatePendingIncoming {
					icon = Style.Bell
					status = "INCOMING REQUEST"
				} else if c.Connecting {
					icon = Style.Searching
					status = "SEARCHING..."
				} else if c.Presence == f2f.PresenceOnline {
					icon = Style.Online
					status = "ONLINE"
				}

				lines = append(lines, fmt.Sprintf("%s %-12s %s", icon, c.Nickname, status))
			}
			ui.DrawBox("КОНТАКТЫ", lines)

		case ".check":
			ui.OnLog(f2f.LogLevelInfo, "Проверка статусов...")
			node.ForceCheckAll()

		case ".find":
			if len(parts) > 1 {
				go node.FindContact(parts[1])
			}

		case ".rec":
			handleRecord(ui, node, rl, parts)

		case ".play":
			handlePlay(ui, parts)

		case ".settings":
			handleSettings(ui, rl)

		case ".voicecall":
			target := pickCallTarget(node, parts, false)
			if target == "" {
				ui.OnLog(f2f.LogLevelInfo, "Использование: .voicecall [<nick>] (или в активном чате)")
			} else if err := node.InitiateCall(target); err != nil {
				ui.OnLog(f2f.LogLevelError, "Звонок: %v", err)
			}

		case ".videocall":
			target := pickCallTarget(node, parts, false)
			if target == "" {
				ui.OnLog(f2f.LogLevelInfo, "Использование: .videocall [<nick>] (или в активном чате)")
				break
			}
			// Make sure ffmpeg is available if settings point at camera.
			s := f2f.LoadSettings()
			wantsCamera := s.VideoSourceType == "camera" ||
				(s.VideoSourceType == "" && s.VideoCameraID != "")
			if wantsCamera && !ensureFFmpegInstalled(ui) {
				break
			}
			if err := node.InitiateCall(target); err != nil {
				ui.OnLog(f2f.LogLevelError, "Звонок: %v", err)
				break
			}
			// Watch for CallActive state, then start outgoing video.
			go autoStartVideoOnAccept(node, ui, target)

		case ".acceptcall":
			target := pickCallTarget(node, parts, true)
			if target == "" {
				ui.OnLog(f2f.LogLevelInfo, "Нет входящих вызовов")
			} else if err := node.AcceptCall(target); err != nil {
				ui.OnLog(f2f.LogLevelError, "Приём: %v", err)
			}

		case ".declinecall":
			target := pickCallTarget(node, parts, true)
			if target == "" {
				ui.OnLog(f2f.LogLevelInfo, "Нет входящих вызовов")
			} else if err := node.DeclineCall(target); err != nil {
				ui.OnLog(f2f.LogLevelError, "Отказ: %v", err)
			}

		case ".hangup":
			target := pickCallTarget(node, parts, false)
			if target == "" {
				ui.OnLog(f2f.LogLevelInfo, "Нет активных вызовов")
			} else if err := node.EndCall(target); err != nil {
				ui.OnLog(f2f.LogLevelError, "Отбой: %v", err)
			}

		case ".video":
			target := pickCallTarget(node, nil, false)
			if target == "" {
				ui.OnLog(f2f.LogLevelInfo, "Видео работает только во время активного .voicecall")
				break
			}
			source := ""
			if len(parts) > 1 {
				source = strings.Join(parts[1:], " ")
			}
			// If user selected camera (explicitly or via settings default),
			// ensure ffmpeg is installed before proceeding.
			wantsCamera := strings.EqualFold(source, "camera") ||
				strings.EqualFold(source, "cam") ||
				strings.EqualFold(source, "webcam")
			if !wantsCamera && source == "" {
				s := f2f.LoadSettings()
				wantsCamera = s.VideoSourceType == "camera" ||
					(s.VideoSourceType == "" && s.VideoCameraID != "")
			}
			if wantsCamera && !ensureFFmpegInstalled(ui) {
				break
			}
			if err := node.StartVideoFrom(target, source); err != nil {
				ui.OnLog(f2f.LogLevelError, "Видео: %v", err)
			}

		case ".cameras":
			// Diagnostic: enumerate cameras verbosely, show raw ffmpeg output.
			if !ensureFFmpegInstalled(ui) {
				break
			}
			cams, raw, err := f2f.ListCamerasVerbose()
			if err != nil {
				ui.OnLog(f2f.LogLevelError, "%v", err)
			} else if len(cams) == 0 {
				ui.OnLog(f2f.LogLevelWarning, "Камер не найдено.")
			} else {
				ui.OnLog(f2f.LogLevelSuccess, "Найдено %d камер(ы):", len(cams))
				for i, c := range cams {
					ui.OnLog(f2f.LogLevelInfo, "  %d) %s", i+1, c)
				}
			}
			if raw != "" {
				ui.OnLog(f2f.LogLevelInfo, "Сырой ответ ffmpeg:")
				for _, l := range strings.Split(raw, "\n") {
					l = strings.TrimRight(l, "\r\n ")
					if l != "" {
						fmt.Printf("  │ %s\n", l)
					}
				}
			}

		case ".ffmpeg":
			// .ffmpeg install — force download even if PATH already has one
			// .ffmpeg         — check status
			if len(parts) > 1 && parts[1] == "install" {
				ensureFFmpegInstalled(ui)
			} else if p := f2f.ResolveFFmpeg(); p != "" {
				ui.OnLog(f2f.LogLevelInfo, "ffmpeg: %s", p)
			} else {
				ui.OnLog(f2f.LogLevelWarning, "ffmpeg не найден — .ffmpeg install чтобы скачать")
			}

		case ".stopvideo":
			target := pickCallTarget(node, nil, false)
			if target == "" {
				ui.OnLog(f2f.LogLevelInfo, "Нет активного вызова")
				break
			}
			if err := node.StopVideo(target); err != nil {
				ui.OnLog(f2f.LogLevelError, "Стоп видео: %v", err)
			}

		case ".help":
			ui.PrintHelp()

		case ".exit", ".quit":
			node.Shutdown()
			return

		default:
			ui.OnLog(f2f.LogLevelWarning, "Неизвестная команда. Введите .help")
		}
	}
	node.Shutdown()
}


func enableANSI() {
	if runtime.GOOS == "windows" {
		// Just a placeholder
	}
}

func getPassword(ui *ConsoleAdapter) (string, error) {
	isNew := f2f.IsNewUser()

	if isNew {
		ui.DrawBox("НОВЫЙ ПОЛЬЗОВАТЕЛЬ", []string{
			"Создайте мастер-пароль для защиты ваших данных.",
			"Шифрование: XChaCha20-Poly1305 + Argon2id (256 MB).",
			"",
			"Рекомендации:",
			" • passphrase из 4+ несвязанных слов, ИЛИ",
			" • 16+ случайных символов с цифрами и знаками",
			" • минимум 12 символов",
			"",
			"ВНИМАНИЕ: Пароль нельзя восстановить!",
		})
	} else {
		// Show saved hint (if any) BEFORE prompting — helps the legitimate
		// user remember, and is stored in plaintext by design.
		if hint := f2f.LoadPasswordHint(); hint != "" {
			ui.OnLog(f2f.LogLevelInfo, "Подсказка: %s", hint)
		}
		ui.OnLog(f2f.LogLevelInfo, "Введите мастер-пароль:")
	}

	fmt.Print("Пароль: ")
	password, err := readPasswordMasked()
	if err != nil {
		return "", err
	}

	if isNew {
		fmt.Print("Подтвердите пароль: ")
		confirm, err := readPasswordMasked()
		if err != nil {
			return "", err
		}

		if password != confirm {
			return "", fmt.Errorf("пароли не совпадают")
		}

		if len(password) < 8 {
			return "", fmt.Errorf("пароль слишком короткий (минимум 8 символов)")
		}

		// Optional hint prompt. Use the same byte-at-a-time reader so that
		// whatever commands the user pipes after the hint reach readline.
		fmt.Print("Подсказка к паролю (Enter — пропустить): ")
		hintRaw, err := readPipedLine()
		if err != nil && len(hintRaw) == 0 {
			return "", err
		}
		hint := strings.TrimSpace(hintRaw)
		if hint != "" {
			if err := f2f.SavePasswordHint(hint); err != nil {
				ui.OnLog(f2f.LogLevelWarning, "Не удалось сохранить подсказку: %v", err)
			} else {
				ui.OnLog(f2f.LogLevelSuccess, "Подсказка сохранена (хранится открытым текстом в %s)", f2f.HintFile)
			}
		}
	}

	return password, nil
}

// readPipedLine reads a single line from stdin byte-by-byte. We avoid a
// buffered reader here because readline (used later in the REPL loop) also
// reads from os.Stdin — any buffered look-ahead would be lost to readline
// and the user would see their commands vanish.
func readPipedLine() (string, error) {
	var b [1]byte
	var line []byte
	for {
		_, err := os.Stdin.Read(b[:])
		if err != nil {
			if len(line) == 0 {
				return "", err
			}
			break
		}
		if b[0] == '\n' {
			break
		}
		line = append(line, b[0])
	}
	fmt.Println()
	return strings.TrimRight(string(line), "\r"), nil
}

// readPasswordMasked reads a password echoing "*" for each rune typed.
// Falls back to plain line read if raw mode isn't available (piped stdin etc).
func readPasswordMasked() (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		// Non-interactive stdin (pipe/redirect) — no echo possible and
		// term.ReadPassword fails on Windows pipe handles with "handle is
		// invalid", so fall back to a plain line read from the shared reader.
		return readPipedLine()
	}

	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return readPipedLine()
	}
	defer term.Restore(fd, oldState)

	reader := bufio.NewReader(os.Stdin)
	var runes []rune
	for {
		r, _, err := reader.ReadRune()
		if err != nil {
			return "", err
		}
		switch r {
		case '\r', '\n':
			fmt.Print("\r\n")
			return string(runes), nil
		case 3: // Ctrl+C
			fmt.Print("\r\n")
			return "", fmt.Errorf("ввод отменён")
		case 8, 127: // Backspace / DEL
			if len(runes) > 0 {
				runes = runes[:len(runes)-1]
				fmt.Print("\b \b")
			}
		default:
			if unicode.IsPrint(r) {
				runes = append(runes, r)
				fmt.Print("*")
			}
		}
	}
}

func printNodeInfo(ui *ConsoleAdapter, node *f2f.Node) {
	if node.GetNickname() == "" {
		ui.OnLog(f2f.LogLevelWarning, "Вы не залогинены")
		return
	}

	peers, hasRelay := node.GetNetworkStatus()

	var statusLine string
	if hasRelay {
		statusLine = fmt.Sprintf("%s GLOBAL (relay)", Style.Global)
	} else if peers > 0 {
		statusLine = fmt.Sprintf("%s ONLINE", Style.Online)
	} else {
		statusLine = fmt.Sprintf("%s OFFLINE", Style.Offline)
	}

	rawString := node.GetIdentityString()
	idParts := strings.Fields(rawString)

	var lines []string
	lines = append(lines, fmt.Sprintf("Ник:    %s", node.GetNickname()))
	lines = append(lines, fmt.Sprintf("Статус: %s", statusLine))
	lines = append(lines, fmt.Sprintf("Пиров:  %d", peers))
	lines = append(lines, fmt.Sprintf("PeerID: %s", node.GetHostID()))

	if len(idParts) >= 4 {
		pubKey := idParts[3]
		bytes, _ := base64.StdEncoding.DecodeString(pubKey)
		fp := f2f.ComputeFingerprint(bytes)
		lines = append(lines, fmt.Sprintf("FP:     %s", fp))
		lines = append(lines, "")
		lines = append(lines, "Команда для друга:")
		lines = append(lines, rawString)
	}

	ui.DrawBox("ВАШИ ДАННЫЕ", lines)
}
