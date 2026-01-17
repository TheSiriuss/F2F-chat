package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/TheSiriuss/F2F-chat/pkg/f2f"
	"github.com/chzyer/readline"
	"golang.org/x/term"
	"os"
)

func main() {
	initStyle()

	rl, err := readline.NewEx(&readline.Config{
		Prompt:          "> ",
		InterruptPrompt: "^C",
		EOFPrompt:       ".exit",
	})
	if err != nil {
		panic(err)
	}
	defer func() { _ = rl.Close() }()

	ui := &ConsoleAdapter{rl: rl}

	fmt.Print("\033[H\033[2J")
	ui.PrintBanner()

	// === НОВОЕ: Ввод пароля ===
	password, err := getPassword(ui)
	if err != nil {
		fmt.Println("Ошибка:", err)
		return
	}

	ctx := context.Background()
	node, err := f2f.NewNode(ctx, ui, password)
	if err != nil {
		if err == f2f.ErrWrongPassword {
			fmt.Println("Неверный пароль!")
		} else {
			fmt.Println("Critical Error:", err)
		}
		return
	}

	if err := node.LoadContacts(); err != nil {
		// Тихий фейл
	}

	if node.GetNickname() != "" {
		ui.OnLog(f2f.LogLevelSuccess, "Авто-вход: %s", node.GetNickname())
		go func() {
			time.Sleep(200 * time.Millisecond)
			printNodeInfo(ui, node)
		}()
	} else {
		ui.OnLog(f2f.LogLevelInfo, "Введите .login <ник> для создания профиля")
	}

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
					fmt.Printf("[Вы %s]: %s\n", time.Now().Format("15:04"), cleanMsg)
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

		case ".fingerprint":
			if len(parts) > 1 {
				ui.OnLog(f2f.LogLevelInfo, "Пока работает только для своего ключа (без аргументов)")
			} else {
				idStr := node.GetIdentityString()
				parts := strings.Fields(idStr)
				if len(parts) >= 4 {
					pubKeyBytes, _ := base64.StdEncoding.DecodeString(parts[3])
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

// getPassword запрашивает пароль у пользователя
func getPassword(ui *ConsoleAdapter) (string, error) {
	isNew := f2f.IsNewUser()

	if isNew {
		ui.DrawBox("НОВЫЙ ПОЛЬЗОВАТЕЛЬ", []string{
			"Создайте мастер-пароль для защиты ваших данных.",
			"Пароль шифрует identity и контакты.",
			"ВНИМАНИЕ: Пароль нельзя восстановить!",
		})
	} else {
		ui.OnLog(f2f.LogLevelInfo, "Введите мастер-пароль:")
	}

	fmt.Print("Пароль: ")
	password, err := readPassword()
	if err != nil {
		return "", err
	}
	fmt.Println()

	if isNew {
		// Подтверждение пароля для нового пользователя
		fmt.Print("Подтвердите пароль: ")
		confirm, err := readPassword()
		if err != nil {
			return "", err
		}
		fmt.Println()

		if password != confirm {
			return "", fmt.Errorf("пароли не совпадают")
		}

		if len(password) < 8 {
			return "", fmt.Errorf("пароль слишком короткий (минимум 8 символов)")
		}
	}

	return password, nil
}

// readPassword читает пароль без эха
func readPassword() (string, error) {
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	return string(password), nil
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
	parts := strings.Fields(rawString)

	var lines []string
	lines = append(lines, fmt.Sprintf("Ник:    %s", node.GetNickname()))
	lines = append(lines, fmt.Sprintf("Статус: %s", statusLine))
	lines = append(lines, fmt.Sprintf("Пиров:  %d", peers))
	lines = append(lines, fmt.Sprintf("PeerID: %s", node.GetHostID()))

	if len(parts) >= 4 {
		pubKey := parts[3]
		bytes, _ := base64.StdEncoding.DecodeString(pubKey)
		fp := f2f.ComputeFingerprint(bytes)
		lines = append(lines, fmt.Sprintf("FP:     %s", fp))
		lines = append(lines, "")
		lines = append(lines, "Команда для друга:")
		lines = append(lines, rawString)
	}

	ui.DrawBox("ВАШИ ДАННЫЕ", lines)
}
