package tui

import (
	"fmt"
	"strings"

	"github.com/atotto/clipboard"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/TheSiriuss/aski-chat/pkg/aski"
)

// -----------------------------------------------------------------------------
// Command palette / slash commands
// -----------------------------------------------------------------------------

// runCommand parses a palette entry and returns a tea.Cmd that invokes the
// corresponding f2f.Node method. No output — results come back via the
// UIListener → Adapter → tea.Msg pipeline.
func (m *Model) runCommand(raw string) tea.Cmd {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Fields(raw)
	cmd := strings.ToLower(parts[0])
	args := parts[1:]
	node := m.node

	switch cmd {
	case "q", "quit", "exit":
		return tea.Quit

	case "help", "?":
		m.focus = focusHelp
		return nil

	case "login":
		if len(args) < 1 {
			return notice("usage: login <nick>")
		}
		go node.Login(args[0])

	case "logout":
		go node.Logout()

	case "info":
		return showInfoPanel()

	case "fingerprint", "fp":
		return showFingerprintPanel()

	case "copy":
		raw := node.GetIdentityString()
		if !strings.HasPrefix(raw, ".addfriend ") {
			return notice("сначала .login <nick>")
		}
		if err := clipboard.WriteAll(raw); err != nil {
			return notice("буфер обмена недоступен: " + err.Error())
		}
		return notice("[OK] .addfriend скопирована — шли друзьям")

	case "bootstrap":
		go node.ConnectToBootstrap()

	case "addfriend", "add":
		if len(args) < 3 {
			return notice("usage: addfriend <nick> <peerID> <pubkeyB64>")
		}
		go node.AddFriend(args[0], args[1], args[2])

	case "removefriend", "rm":
		if len(args) < 1 {
			return notice("usage: removefriend <nick>")
		}
		go node.RemoveFriend(args[0])

	case "connect", "open":
		if len(args) < 1 {
			return notice("usage: connect <nick>")
		}
		go node.InitConnect(args[0])

	case "disconnect":
		target := firstArgOrActive(args, m)
		if target == "" {
			return notice("нет активного чата")
		}
		go node.Disconnect(target)

	case "accept":
		target := firstArgOrActive(args, m)
		if target == "" {
			return notice("нет входящего запроса")
		}
		go node.HandleDecision(target, true)

	case "decline":
		target := firstArgOrActive(args, m)
		if target == "" {
			return notice("нет входящего запроса")
		}
		go node.HandleDecision(target, false)

	case "leave":
		go node.LeaveChat()

	case "check", "status":
		go node.ForceCheckAll()

	case "find":
		if len(args) < 1 {
			return notice("usage: find <nick>")
		}
		go node.FindContact(args[0])

	case "list":
		return tea.Batch(refreshContactsCmd(node), showContactsPanel())

	// --- files ---
	case "file", "send":
		target := m.activeNick()
		if target == "" {
			return notice("сначала открой чат")
		}
		if len(args) < 1 {
			return notice("usage: file <path>")
		}
		path := strings.Join(args, " ")
		active := node.GetActiveChat()
		if active.String() == "" {
			return notice("чат не активен")
		}
		go node.SendFile(active, path)

	case "getfile":
		return funcCmd(func() { _ = node.AcceptFile("") })
	case "nofile":
		return funcCmd(func() { _ = node.DeclineFile("") })

	// --- voice messages ---
	case "rec":
		return notice("используй старый CLI для .rec (WIP в новой TUI)")
	case "play":
		if len(args) < 1 {
			return notice("usage: play <path>")
		}
		path := strings.Join(args, " ")
		return funcCmd(func() {
			s := f2f.LoadSettings()
			_ = f2f.PlayWAV(s.AudioOutputDeviceID, path)
		})

	// --- calls (independent of .connect — own libp2p protocol) ---
	case "call", "voicecall":
		target := firstArgOrActive(args, m)
		if target == "" {
			return notice("usage: call <nick>")
		}
		return voiceCall(node, target)

	case "vidcall", "videocall":
		target := firstArgOrActive(args, m)
		if target == "" {
			return notice("usage: vidcall <nick>")
		}
		return videoCall(node, target)

	case "acceptcall":
		target := callTargetOrActive(args, node, m, f2f.CallIncoming)
		if target == "" {
			return notice("нет входящего вызова")
		}
		return func() tea.Msg {
			if err := node.AcceptCall(target); err != nil {
				return MsgLog{Level: f2f.LogLevelError, Format: "Не удалось принять вызов: " + err.Error()}
			}
			return nil
		}

	case "declinecall":
		target := callTargetOrActive(args, node, m, f2f.CallIncoming)
		if target == "" {
			return notice("нет входящего вызова")
		}
		return funcCmd(func() { _ = node.DeclineCall(target) })

	case "hangup":
		// Accept ANY non-idle call state (outgoing / incoming / active):
		// user should be able to bail from a ringing call too.
		target := callTargetOrActive(args, node, m, -1)
		if target == "" {
			return notice("нет активного вызова")
		}
		return func() tea.Msg {
			if err := node.EndCall(target); err != nil {
				return MsgLog{Level: f2f.LogLevelWarning, Format: "Завершить вызов с " + target + ": " + err.Error()}
			}
			return nil
		}

	case "video":
		target := m.activeNick()
		if target == "" {
			return notice("нет активного вызова")
		}
		source := ""
		if len(args) > 0 {
			source = strings.Join(args, " ")
		}
		return funcCmd(func() { _ = node.StartVideoFrom(target, source) })

	case "stopvideo":
		target := m.activeNick()
		if target == "" {
			return nil
		}
		return funcCmd(func() { _ = node.StopVideo(target) })

	case "cameras":
		return func() tea.Msg { return MsgSystemPanel{Kind: "cameras"} }

	// --- settings ---
	case "settings":
		return handleSettingsCmd(args)

	// --- ffmpeg (status / install) ---
	case "ffmpeg":
		return handleFFmpegCmd(node, args)

	// --- UI language ---
	case "language", "lang":
		return handleLanguageCmd(args)

	default:
		return notice(fmt.Sprintf("неизвестная команда: %s (? — список)", cmd))
	}
	return nil
}

// sendText sends a chat message to the currently active peer.
func (m *Model) sendText(text string) tea.Cmd {
	active := m.node.GetActiveChat()
	if active.String() == "" {
		return notice("сначала открой чат (сайдбар → Enter) или /connect <nick>")
	}
	clean := f2f.SanitizeInput(text, f2f.MaxMsgLength)
	if clean == "" {
		return nil
	}
	go m.node.SendChatMessage(active, clean)
	return nil
}

// -----------------------------------------------------------------------------
// Small helpers
// -----------------------------------------------------------------------------

// firstArgOrActive returns args[0] if present, else the active chat's nick.
func firstArgOrActive(args []string, m *Model) string {
	if len(args) > 0 {
		return args[0]
	}
	return m.activeNick()
}

// callTargetOrActive picks the nickname to apply a call-scoped command to:
//
//  1. explicit arg wins
//  2. otherwise: any contact currently in the requested call state
//     (wantState < 0 means "any non-idle call")
//  3. otherwise: active chat nick
//
// Uses node.GetContactState and nickname via contact iteration — since
// Contact.mu is not exported, we can't RLock from here. Instead we rely
// on the atomicity of pointer reads + the node's GetContactCallState helper.
func callTargetOrActive(args []string, node *f2f.Node, m *Model, wantState f2f.CallState) string {
	if len(args) > 0 {
		return args[0]
	}
	for _, c := range node.GetContacts() {
		st := node.GetCallState(c.Nickname)
		if st == f2f.CallIdle {
			continue
		}
		if wantState < 0 || st == wantState {
			return c.Nickname
		}
	}
	return m.activeNick()
}

// activeNick returns the nickname for the currently open chat contact.
func (m *Model) activeNick() string {
	if m.activeChat.String() == "" {
		return ""
	}
	for _, c := range m.contacts {
		if c.PeerID == m.activeChat {
			return c.Nickname
		}
	}
	return ""
}

// funcCmd wraps a synchronous function call in a tea.Cmd that returns nil.
// Real UI updates come back via UIListener → Adapter.
func funcCmd(fn func()) tea.Cmd {
	return func() tea.Msg {
		fn()
		return nil
	}
}

// notice creates a tea.Cmd that surfaces a one-shot notice in the footer.
func notice(text string) tea.Cmd {
	return func() tea.Msg {
		return MsgLog{Level: f2f.LogLevelInfo, Format: text}
	}
}

// -----------------------------------------------------------------------------
// Panel commands — emit MsgSystemPanel so the chat history surfaces a
// proper formatted box (lipgloss-bordered) rather than a single-line log.
// -----------------------------------------------------------------------------

// Panel emitters: just request a Kind; rendering happens in Update with
// the current chat-pane width.

func showInfoPanel() tea.Cmd {
	return func() tea.Msg { return MsgSystemPanel{Kind: "info"} }
}

func showFingerprintPanel() tea.Cmd {
	return func() tea.Msg { return MsgSystemPanel{Kind: "fingerprint"} }
}

func showContactsPanel() tea.Cmd {
	return func() tea.Msg { return MsgSystemPanel{Kind: "contacts"} }
}

func showWelcomePanel() tea.Cmd {
	return func() tea.Msg { return MsgSystemPanel{Kind: "welcome"} }
}

