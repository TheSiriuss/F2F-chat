package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/chzyer/readline"
)

func main() {
	initStyle()

	// Parse command line arguments
	for _, arg := range os.Args[1:] {
		switch arg {
		case "--debug":
			DebugMode = true
			fmt.Println("[SYS] Debug mode ENABLED")
		case "--ascii":
			os.Setenv("F2F_ASCII", "1")
			initStyle()
		case "--help":
			fmt.Println("F2F Messenger Alpha")
			fmt.Println("Usage: f2f-messenger [--debug] [--ascii]")
			return
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fmt.Println("Запуск F2F Alpha...")
	node, err := NewNode(ctx)
	if err != nil {
		fmt.Println("Критическая ошибка:", err)
		os.Exit(1)
	}

	// Handle signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println()
		node.Shutdown()
		os.Exit(0)
	}()

	// Load contacts
	if err := node.LoadContacts(); err != nil {
		node.Debug("Контакты не найдены: %v", err)
	}

	// Try readline
	rl, err := readline.NewEx(&readline.Config{
		Prompt:          "> ",
		InterruptPrompt: "^C",
		EOFPrompt:       ".exit",
	})
	if err == nil {
		node.rl = rl
		node.useReadline = true
	} else {
		node.useReadline = false
		fmt.Printf("[SYS] Readline недоступен, простой режим\n")
	}

	// Clear screen and show banner
	fmt.Print("\033[H\033[2J")
	node.printBanner()

	if node.nickname != "" {
		node.SafePrintf("%s Авто-вход: %s\n", Style.OK, node.nickname)
		go func() {
			time.Sleep(200 * time.Millisecond)
			node.ShowInfo()
		}()
	} else {
		node.SafePrintf("%s Введите .login <ник> для создания профиля\n", Style.Info)
	}

	// Main loop
	if node.useReadline {
		node.runWithReadline()
	} else {
		node.runWithScanner()
	}

	node.Shutdown()
}

// runWithReadline runs main loop with readline
func (n *Node) runWithReadline() {
	defer func() {
		if n.rl != nil {
			n.rl.Close()
		}
	}()

	for {
		n.updatePrompt()
		line, err := n.rl.Readline()
		if err != nil {
			if err == readline.ErrInterrupt {
				fmt.Println()
				return
			}
			return
		}

		if !n.processInputLine(line) {
			return
		}
	}
}

// runWithScanner runs main loop with scanner (fallback)
func (n *Node) runWithScanner() {
	scanner := bufio.NewScanner(os.Stdin)
	n.printPrompt()

	for scanner.Scan() {
		line := scanner.Text()
		if !n.processInputLine(line) {
			return
		}
		n.printPrompt()
	}
}

// processInputLine processes a single input line, returns false to exit
func (n *Node) processInputLine(line string) bool {
	line = strings.TrimSpace(line)
	if line == "" {
		return true
	}

	n.mu.RLock()
	currentChatID := n.activeChat
	n.mu.RUnlock()

	// If in chat and not a command, send as message
	if currentChatID != "" && !strings.HasPrefix(line, ".") {
		cleanMsg := SanitizeInput(line, MaxMsgLength)
		if cleanMsg != "" {
			n.SendChatMessage(currentChatID, cleanMsg)
		}
		return true
	}

	parts := strings.Fields(line)
	if len(parts) == 0 {
		return true
	}
	cmd := strings.ToLower(parts[0])

	switch cmd {
	case ".login":
		if len(parts) < 2 {
			n.SafePrintf("Использование: .login <nickname>\n")
		} else {
			cleanNick := SanitizeInput(parts[1], MaxNickLength)
			n.Login(cleanNick)
		}

	case ".logout":
		n.SafePrintf("%s Сброс личности...\n", Style.Warning)
		if err := os.Remove(IdentityFile); err != nil {
			n.SafePrintf("%s Ошибка: %v\n", Style.Fail, err)
		} else {
			n.SafePrintf("%s Удалено. Перезапустите программу.\n", Style.OK)
			return false
		}

	case ".bootstrap":
		n.ConnectToBootstrap()

	case ".info":
		n.ShowInfo()

	case ".fingerprint":
		if len(parts) < 2 {
			n.ShowFingerprint("")
		} else {
			n.ShowFingerprint(parts[1])
		}

	case ".addfriend":
		if len(parts) >= 4 {
			n.AddFriend(parts[1], parts[2], parts[3])
		} else {
			n.SafePrintf("Использование: .addfriend <nick> <peerID> <pubkey>\n")
		}

	case ".connect":
		if len(parts) < 2 {
			n.SafePrintf("Использование: .connect <nickname>\n")
		} else {
			go n.InitConnect(parts[1])
		}

	case ".accept":
		if len(parts) < 2 {
			n.SafePrintf("Использование: .accept <nickname>\n")
		} else {
			n.HandleDecision(parts[1], true)
		}

	case ".decline":
		if len(parts) < 2 {
			n.SafePrintf("Использование: .decline <nickname>\n")
		} else {
			n.HandleDecision(parts[1], false)
		}

	case ".leave":
		n.LeaveChat()

	case ".list":
		n.ListContacts()

	case ".check":
		n.SafePrintf("%s Проверка контактов...\n", Style.Info)
		n.ForceCheckAll()

	case ".find":
		if len(parts) < 2 {
			n.SafePrintf("Использование: .find <nickname>\n")
		} else {
			go n.FindContact(parts[1])
		}

	case ".help":
		n.printHelp()

	case ".exit", ".quit", ".q":
		n.SafePrintf("%s Выход...\n", Style.Info)
		return false

	default:
		n.SafePrintf("%s Неизвестная команда. .help\n", Style.Warning)
	}

	return true
}
