package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/TheSiriuss/aski/pkg/aski"
)

// stripControls removes ASCII control characters (except TAB/space) from
// a clipboard paste. Windows clipboards sometimes carry \r\n endings and
// stray BOMs that would corrupt our one-line input.
func stripControls(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == '\r' || r == '\n' {
			continue
		}
		if r < 0x20 && r != '\t' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// -----------------------------------------------------------------------------
// focus zones — what the keyboard controls right now
// -----------------------------------------------------------------------------

type focus int

const (
	focusChat focus = iota // arrow keys scroll chat, typing goes to input
	focusSidebar
	focusHelp // help overlay open
)

// -----------------------------------------------------------------------------
// ChatEntry — one rendered line in the chat log. Covers messages, system
// notices, file events, video-frame notifications. Kept as rendered strings
// so scrolling is cheap.
// -----------------------------------------------------------------------------

type ChatEntry struct {
	Timestamp time.Time
	Rendered  string // pre-styled string to print in the chat viewport
	// Kind tags dynamic-width panels so they get re-rendered when the
	// terminal is resized. Empty = static content (chat messages, logs).
	Kind string
}

// activeCallView holds the state for the dedicated call pane that
// replaces the chat log while a call is in progress.
type activeCallView struct {
	PeerID  string
	Nick    string
	Kind    string // "voice" or "video"
	Started time.Time
}


// -----------------------------------------------------------------------------
// Model
// -----------------------------------------------------------------------------

type Model struct {
	node *f2f.Node

	// Layout dimensions
	width, height int

	// startupShown becomes true once the welcome + info panels have been
	// emitted (after the first WindowSizeMsg arrives). We defer those
	// emissions out of Init so panels render at the correct chat width.
	startupShown bool

	// Styles
	sty styles

	// UI state
	focus       focus
	sidebarIdx  int
	activeChat  peer.ID // empty = no chat selected
	showOverlay bool

	// activeCall — when non-nil, the main pane shows a dedicated call
	// view (ASCII video frame / placeholder) instead of the chat log.
	// Set on MsgCallActive, cleared on MsgCallEnded.
	activeCall *activeCallView

	// Components
	input textinput.Model
	chat  viewport.Model

	// IDE-style autocomplete state for dot-commands. When the input
	// starts with ".", suggestions is the filtered command list and
	// suggestIdx is the highlighted row.
	commands    []commandDef
	suggestions []commandDef
	suggestIdx  int

	// Per-contact chat history. Key = peer.ID (string form, since peer.ID
	// is a string underneath). System messages without a peer go under "".
	history map[string][]ChatEntry

	// Unread counts per peer ID.
	unread map[string]int

	// Cached contacts list (sorted), refreshed on MsgContactUpdate.
	contacts []*f2f.Contact

	// Incoming video frame (per peer) — most recent ASCII frame. Shown
	// inline in the chat area when you're talking to that peer.
	videoFrame map[string]string

	// Status line data
	dhtPeers int
	hasRelay bool

	// Last global notification (shown briefly in footer)
	lastNotice    string
	lastNoticeTS  time.Time
	lastNoticeLvl string
}

func NewModel(node *f2f.Node) Model {
	// Load UI language from settings so persistence works across runs.
	s := f2f.LoadSettings()
	if s.Language != "" {
		SetLanguage(s.Language)
	}

	in := textinput.New()
	in.Prompt = ""
	in.CharLimit = 4000
	in.Placeholder = "сообщение, или . для команд"
	in.Focus()

	return Model{
		node:       node,
		sty:        newStyles(),
		input:      in,
		chat:       viewport.New(0, 0),
		commands:   allCommands(),
		history:    map[string][]ChatEntry{},
		unread:     map[string]int{},
		videoFrame: map[string]string{},
	}
}

func (m Model) Init() tea.Cmd {
	// Welcome/info panels are deferred until the first WindowSizeMsg (see
	// Update) so they render at the correct chat-pane width. Init just
	// kicks off infrastructure.
	return tea.Batch(
		textinput.Blink,
		tickCmd(),
		refreshContactsCmd(m.node),
	)
}

// -----------------------------------------------------------------------------
// Update
// -----------------------------------------------------------------------------

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.resize()
		// Re-render any dynamic panels (info/contacts/welcome) using the
		// new width so they don't get stuck at the old layout.
		m.rerenderDynamicPanels()
		// First-ever resize → spawn the welcome + info panels now that
		// width is known.
		if !m.startupShown {
			m.startupShown = true
			cmds = append(cmds, showWelcomePanel())
			if m.node != nil && m.node.GetNickname() != "" {
				cmds = append(cmds, showInfoPanel())
			}
		}
		return m, tea.Batch(cmds...)

	case tea.KeyMsg:
		return m.handleKey(msg)

	case MsgTick:
		cmds = append(cmds, tickCmd())
		// Expire old transient notices.
		if !m.lastNoticeTS.IsZero() && time.Since(m.lastNoticeTS) > 4*time.Second {
			m.lastNotice = ""
		}
		// Keep header status (peer count, relay) live.
		if m.node != nil {
			m.dhtPeers, m.hasRelay = m.node.GetNetworkStatus()
		}
		// Keep any visible .info / .list panels live too — their peer
		// count and contact statuses would otherwise freeze at snapshot
		// time. Also re-pull the contacts list so icon indicators react
		// to presence-check results without waiting for a state change
		// event.
		cmds = append(cmds, refreshContactsCmd(m.node))
		m.rerenderDynamicPanels()

	case contactsRefreshedMsg:
		m.contacts = msg.list
		m.clampSidebar()
		// The .list panel rendered earlier holds a stale view of the
		// contact list; re-render so the new statuses land in the UI.
		m.rerenderDynamicPanels()

	case MsgContactUpdate:
		cmds = append(cmds, refreshContactsCmd(m.node))
		m.rerenderDynamicPanels()

	case MsgChatMessage:
		// Self-echo: when Node emits OnMessage for a message we JUST sent,
		// msg.PeerID is our own host ID — but visually the user expects
		// that line inside the conversation they typed it into, not a
		// hidden self-history. Route it to activeChat.
		routeKey := msg.PeerID
		if m.node != nil && msg.PeerID == m.node.GetHostID() {
			routeKey = m.activeChat.String()
		}
		entry := m.renderChatMessage(msg)
		m.appendEntry(routeKey, entry)
		if m.activeChat.String() != routeKey {
			m.unread[routeKey]++
		} else {
			m.chat.GotoBottom()
		}
		m.refreshChatViewport()

	case MsgFileOffer:
		entry := ChatEntry{
			Timestamp: time.Now(),
			Rendered: m.sty.msgSystem.Render(fmt.Sprintf(
				"[file] %s предлагает файл: %s (%s) — /getfile", msg.Nick, msg.Filename, humanBytes(msg.Size))),
		}
		m.appendEntry(msg.PeerID, entry)
		m.refreshChatViewport()

	case MsgFileReceived:
		entry := ChatEntry{
			Timestamp: time.Now(),
			Rendered: m.sty.msgOK.Render(fmt.Sprintf(
				"[recv] %s: %s (%s)", msg.Nick, msg.SavedPath, humanBytes(msg.Size))),
		}
		m.appendEntry(msg.PeerID, entry)
		m.refreshChatViewport()

	case MsgFileProgress:
		// Don't spam the chat log with a progress line per percent — just
		// surface big milestones in the notice line.
		if msg.Progress >= 0.99 {
			direction := "Получен"
			if msg.IsUpload {
				direction = "Отправлен"
			}
			m.setNotice(f2f.LogLevelInfo, fmt.Sprintf("%s %s", direction, msg.Filename))
		}

	case MsgFileComplete:
		if msg.Success {
			m.setNotice(f2f.LogLevelSuccess, "файл "+msg.Filename+": "+msg.Message)
		} else {
			m.setNotice(f2f.LogLevelError, "файл "+msg.Filename+": "+msg.Message)
		}

	case MsgLog:
		txt := fmt.Sprintf(msg.Format, msg.Args...)
		m.setNotice(msg.Level, txt)
		// Persist info/warn/error/success as chat entries so they're
		// scrollable history rather than a 4-second notice. Route to
		// activeChat when one is open so .call / .cameras / connect
		// progress are visible IN the conversation the user is looking at.
		var style = m.sty.msgSystem
		switch msg.Level {
		case f2f.LogLevelError:
			style = m.sty.msgErr
		case f2f.LogLevelWarning:
			style = m.sty.msgWarn
		case f2f.LogLevelSuccess:
			style = m.sty.msgOK
		}
		routeKey := m.activeChat.String()
		entry := ChatEntry{Timestamp: time.Now(), Rendered: style.Render("[*] " + txt)}
		m.appendEntry(routeKey, entry)
		m.refreshChatViewport()

	case MsgChatChanged:
		if msg.PeerID != "" {
			pid, err := peer.Decode(msg.PeerID)
			if err == nil {
				m.activeChat = pid
				m.unread[msg.PeerID] = 0
				m.selectSidebarByPeer(pid)
			}
		} else {
			m.activeChat = ""
		}
		m.refreshChatViewport()

	case MsgVideoFrame:
		m.videoFrame[msg.PeerID] = msg.Frame
		m.refreshChatViewport()

	case MsgSystemPanel:
		// Panels land in the conversation the user is looking at (when
		// one is open) so .info / .list / .cameras / .settings output
		// doesn't disappear into an unseen system history lane.
		routeKey := msg.PeerID
		if routeKey == "" {
			routeKey = m.activeChat.String()
		}
		rendered := m.renderPanel(msg.Kind, msg.Raw)
		m.appendEntry(routeKey, ChatEntry{
			Timestamp: time.Now(),
			Rendered:  rendered,
			Kind:      msg.Kind,
		})
		m.refreshChatViewport()

	case MsgCallIncoming:
		kind := tr("call.voice")
		if msg.Kind == "video" {
			kind = tr("call.video")
		}
		txt := fmt.Sprintf(tr("call.incoming"), kind, msg.Nick, msg.Nick, msg.Nick)
		m.appendCallLog(msg.PeerID, m.sty.msgWarn.Render("[*] "+txt))
		m.setNotice(f2f.LogLevelWarning, txt)
		m.refreshChatViewport()

	case MsgCallOutgoing:
		kind := tr("call.voice")
		if msg.Kind == "video" {
			kind = tr("call.video")
		}
		txt := fmt.Sprintf(tr("call.outgoing"), msg.Nick, kind)
		m.appendCallLog(msg.PeerID, m.sty.msgSystem.Render("[*] "+txt))
		m.setNotice(f2f.LogLevelInfo, txt)
		m.refreshChatViewport()

	case MsgCallActive:
		kind := tr("call.voice")
		if msg.Kind == "video" {
			kind = tr("call.video")
		}
		m.activeCall = &activeCallView{
			PeerID:  msg.PeerID,
			Nick:    msg.Nick,
			Kind:    msg.Kind,
			Started: time.Now(),
		}
		txt := fmt.Sprintf(tr("call.active"), kind, msg.Nick)
		m.appendCallLog(msg.PeerID, m.sty.msgOK.Render("[*] "+txt))
		m.setNotice(f2f.LogLevelSuccess, txt)
		m.refreshChatViewport()

	case MsgCallEnded:
		if m.activeCall != nil && m.activeCall.PeerID == msg.PeerID {
			m.activeCall = nil
		}
		txt := fmt.Sprintf(tr("call.ended"), msg.Nick, msg.Reason, msg.Duration)
		m.appendCallLog(msg.PeerID, m.sty.msgSystem.Render("[*] "+txt))
		m.setNotice(f2f.LogLevelInfo, txt)
		m.refreshChatViewport()
	}

	// Mouse events (wheel scroll) go to the chat viewport.
	if _, ok := msg.(tea.MouseMsg); ok {
		var vpCmd tea.Cmd
		m.chat, vpCmd = m.chat.Update(msg)
		cmds = append(cmds, vpCmd)
	}

	return m, tea.Batch(cmds...)
}

// -----------------------------------------------------------------------------
// Key handling
// -----------------------------------------------------------------------------

func (m Model) handleKey(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	k := key.String()

	// ---- Help overlay: any key closes it. ----
	if m.focus == focusHelp {
		m.focus = focusChat
		m.input.Focus()
		return m, nil
	}

	// ---- Global shortcuts ----
	switch k {
	case "ctrl+c":
		return m, tea.Quit
	case "ctrl+v":
		// Explicit paste — textinput's default binding is ctrl+y.
		// We wire ctrl+v too so Windows users get their muscle memory.
		if pasted, err := clipboard.ReadAll(); err == nil {
			// Drop control chars; keep as single-line insertion.
			pasted = stripControls(pasted)
			m.input.SetValue(m.input.Value() + pasted)
			m.input.CursorEnd()
			m.refreshSuggestions()
		}
		return m, nil
	case "tab":
		// Tab only has meaning for autocompleting a dot-command now.
		if m.focus == focusChat && m.isDotCommand() && len(m.suggestions) > 0 {
			return m.autocomplete(), nil
		}
		return m, nil
	}

	// ---- Chat mode ----
	if m.focus == focusChat {
		// When a dot-command popup is active, arrow keys / Enter drive
		// the SUGGESTIONS, not the chat scroll / message-send.
		if m.isDotCommand() && len(m.suggestions) > 0 {
			switch k {
			case "up":
				if m.suggestIdx > 0 {
					m.suggestIdx--
				}
				return m, nil
			case "down":
				if m.suggestIdx < len(m.suggestions)-1 {
					m.suggestIdx++
				}
				return m, nil
			case "enter":
				// Execute. Three cases:
				//   1. User's typed word is ALREADY a valid command AND
				//      they haven't typed a trailing space — execute it
				//      as-is (".settings" / ".call" / ".info").
				//   2. User typed partial name ("con" → "connect") —
				//      substitute the selected suggestion.
				//   3. User ended with a space (they're drilling into
				//      sub-completions) — run the highlighted suggestion.
				raw := m.input.Value()
				cmd, rest := firstWord(raw)
				endsWithSpace := strings.HasSuffix(raw, " ")

				typedIsExact := false
				for _, c := range m.commands {
					if strings.EqualFold(c.Name, cmd) {
						typedIsExact = true
						break
					}
				}

				// Only treat the typed word as authoritative when no
				// trailing space AND it matches a top-level command.
				// If user typed the space they've left the parent
				// behind and is picking from sub-suggestions.
				useTyped := typedIsExact && !endsWithSpace

				if rest == "" && !useTyped {
					cmd = m.suggestions[m.suggestIdx].Name
				}

				// If the selected command requires args and user hasn't
				// provided any, expand it into the input instead of
				// executing (so user can fill in args).
				sel := m.suggestions[m.suggestIdx]
				if !useTyped && sel.Usage != "" && !strings.HasPrefix(sel.Usage, "[") && rest == "" {
					m.input.SetValue("." + sel.Name + " ")
					m.input.CursorEnd()
					return m, nil
				}
				m.input.Reset()
				m.suggestions = nil
				return m, m.runCommand(cmd + " " + rest)
			case "esc":
				m.input.Reset()
				m.suggestions = nil
				return m, nil
			}
		}

		switch k {
		case "?":
			// Only open help if input is empty; otherwise ? is typed.
			if m.input.Value() == "" {
				m.focus = focusHelp
				return m, nil
			}
		case "enter":
			text := strings.TrimSpace(m.input.Value())
			m.input.Reset()
			m.suggestions = nil
			if text == "" {
				return m, nil
			}
			if strings.HasPrefix(text, ".") {
				return m, m.runCommand(strings.TrimPrefix(text, "."))
			}
			return m, m.sendText(text)
		case "pgup":
			m.chat.HalfViewUp()
			return m, nil
		case "pgdown":
			m.chat.HalfViewDown()
			return m, nil
		case "up":
			if m.input.Value() == "" {
				m.chat.LineUp(1)
				return m, nil
			}
		case "down":
			if m.input.Value() == "" {
				m.chat.LineDown(1)
				return m, nil
			}
		}

		// Forward to textinput and recompute suggestions.
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(key)
		m.refreshSuggestions()
		return m, cmd
	}

	return m, nil
}

// isDotCommand reports whether the current input is a dot-command in progress.
func (m *Model) isDotCommand() bool {
	return strings.HasPrefix(m.input.Value(), ".")
}

// refreshSuggestions recomputes the autocomplete list based on input state.
// Called every keystroke in chat mode.
func (m *Model) refreshSuggestions() {
	if !m.isDotCommand() {
		m.suggestions = nil
		m.suggestIdx = 0
		return
	}
	word, rest := firstWord(m.input.Value())

	// Sub-command context: when the first word is a known parent command
	// that has its own sub-commands (today: only .settings), show the
	// sub-command list instead of top-level commands as soon as the user
	// types a space after the parent.
	if subs := subcommandsFor(word, m); len(subs) > 0 {
		// Match against the FULL typed string (minus the leading dot) so
		// ".settings aut" matches entry "settings autoplay" via prefix.
		fullPrefix := strings.TrimPrefix(m.input.Value(), ".")
		m.suggestions = filterSubcommands(subs, fullPrefix, 256)
		if m.suggestIdx >= len(m.suggestions) {
			m.suggestIdx = 0
		}
		return
	}

	// If the user has typed a complete command + a space, don't obstruct
	// with suggestions anymore — they're entering args now.
	if rest != "" {
		m.suggestions = nil
		return
	}
	m.suggestions = filterCommands(m.commands, word, 256)
	if m.suggestIdx >= len(m.suggestions) {
		m.suggestIdx = 0
	}
}

// subcommandsFor returns a list of sub-command completions for the parent
// command, or nil if none apply. For .settings input / output / camera
// we return the device list as numbered pick options — these get rendered
// in the same suggestion dropdown.
func subcommandsFor(parent string, m *Model) []commandDef {
	switch strings.ToLower(parent) {
	// Commands that take a <nick> — inject the user's contacts list as
	// completions. User types ".connect " (space), sees "connect Bob /
	// connect Alice / ...".
	case "connect", "disconnect", "removefriend", "rm", "call", "voicecall",
		"vidcall", "videocall", "acceptcall", "declinecall", "hangup",
		"accept", "decline", "find":
		val := m.input.Value()
		prefix := "." + strings.ToLower(parent)
		afterParent := strings.TrimPrefix(val, prefix)
		if afterParent == "" || !strings.HasPrefix(afterParent, " ") {
			return nil // only after user typed a space
		}
		return contactSubcommands(m, parent)

	case "settings":
		// Only offer sub-completions once the user has typed a space after
		// ".settings". Before that, they may just want to run ".settings"
		// itself to see the config panel — don't hijack their Enter.
		val := m.input.Value()
		afterParent := strings.TrimPrefix(val, ".settings")
		if afterParent == "" || !strings.HasPrefix(afterParent, " ") {
			return nil
		}

		parts := strings.Fields(afterParent)
		if len(parts) >= 1 {
			sub := strings.ToLower(parts[0])
			// ".settings input " (trailing space) or ".settings input 2"
			// → show device list. ".settings input" (no trailing space)
			// → show settings subs filtered by "input" prefix.
			if strings.HasSuffix(val, " ") || len(parts) >= 2 {
				switch sub {
				case "input":
					return audioDeviceSubcommands(true)
				case "output":
					return audioDeviceSubcommands(false)
				case "camera":
					return cameraSubcommands()
				}
			}
		}
		return settingsSubcommands()
	}
	return nil
}

// contactSubcommands returns one entry per contact, with a short status
// hint (online/offline/in chat) in the Desc column. Fed into
// filterSubcommands so typing ".connect Al" narrows to "Alice".
func contactSubcommands(m *Model, parent string) []commandDef {
	out := make([]commandDef, 0, len(m.contacts))
	for _, c := range m.contacts {
		var status string
		switch {
		case c.State == f2f.StateActive:
			status = "in chat"
		case c.Stream != nil:
			status = "connected"
		case c.State == f2f.StatePendingIncoming:
			status = "incoming request"
		case c.Presence == f2f.PresenceOnline:
			status = "online"
		default:
			status = "offline"
		}
		out = append(out, commandDef{
			Name:  parent + " " + c.Nickname,
			Usage: "",
			Desc:  status,
		})
	}
	return out
}

// settingsSubcommands returns the fixed list of .settings <X> options.
// The Name field encodes the WHOLE sub-path ("settings autoplay") so
// autocomplete substitutes the full phrase back into the input.
func settingsSubcommands() []commandDef {
	return []commandDef{
		{"settings autoplay", "", "переключить автовоспроизв. голосовых"},
		{"settings input", "[N]", "микрофон (без N — список)"},
		{"settings output", "[N]", "колонка (без N — список)"},
		{"settings camera", "[N]", "источник видео (0=ASCII, 1..N=камеры)"},
		{"settings file", "[path|clear]", "файл-заглушка для видео"},
	}
}

// audioDeviceSubcommands enumerates audio devices so autocomplete can
// show them as "settings input 1 | Realtek Microphone" etc.
func audioDeviceSubcommands(wantInput bool) []commandDef {
	sub := "input"
	if !wantInput {
		sub = "output"
	}
	out := []commandDef{
		{"settings " + sub + " 0", "", "(по умолчанию)"},
	}
	devices, err := f2f.ListAudioDevices()
	if err != nil {
		return out
	}
	i := 1
	for _, d := range devices {
		if d.IsInput != wantInput {
			continue
		}
		out = append(out, commandDef{
			Name:  fmt.Sprintf("settings %s %d", sub, i),
			Usage: "",
			Desc:  d.Name,
		})
		i++
	}
	return out
}

// cameraSubcommands enumerates available cameras. Index 0 is always
// the built-in ASCII avatar so users without a camera have a one-click
// choice. 1..N are real ffmpeg-detected webcams.
func cameraSubcommands() []commandDef {
	out := []commandDef{
		{"settings camera 0", "", "ASCII-аватар (без камеры)"},
	}
	if !f2f.CameraAvailable() {
		return out
	}
	cams, _, err := f2f.ListCamerasVerbose()
	if err != nil {
		return out
	}
	for i, c := range cams {
		out = append(out, commandDef{
			Name:  fmt.Sprintf("settings camera %d", i+1),
			Usage: "",
			Desc:  c,
		})
	}
	return out
}

// autocomplete fills in the selected suggestion's name into the input and
// adds a trailing space if the command takes args.
func (m Model) autocomplete() Model {
	if len(m.suggestions) == 0 {
		return m
	}
	sel := m.suggestions[m.suggestIdx]
	value := "." + sel.Name
	if sel.Usage != "" {
		value += " "
	}
	m.input.SetValue(value)
	m.input.CursorEnd()
	m.refreshSuggestions()
	return m
}

// -----------------------------------------------------------------------------
// Internal helpers
// -----------------------------------------------------------------------------

// resize recomputes component dimensions based on window size.
func (m *Model) resize() {
	if m.width < 60 {
		m.width = 60
	}
	if m.height < 20 {
		m.height = 20
	}

	// No sidebar + no wrapping chatPane → viewport fills the full width.
	chatW := m.width - m.sidebarWidth()
	// Rows: header(1) + body + input(3) + footer(1)
	chatH := m.height - 5

	m.chat.Width = chatW
	m.chat.Height = chatH
	m.input.Width = m.width - 4
}

// renderPanel produces a styled panel string based on a Kind tag, using
// the CURRENT chat-pane width. Called both on new emission and when we
// re-render on resize.
func (m *Model) renderPanel(kind, raw string) string {
	w := m.chat.Width
	if w < 40 {
		w = 40
	}
	switch kind {
	case "info":
		return renderInfoBox(m.node, m.sty, w)
	case "contacts":
		return renderContactsBox(m.contacts, m.sty, w)
	case "fingerprint":
		return renderFingerprintBox(m.node, m.sty, w)
	case "welcome":
		return renderWelcomePanel(m.sty, w)
	case "settings":
		return renderSettingsPanel(m.sty, w)
	case "cameras":
		return renderCamerasPanel(m.sty, w)
	case "audio-input":
		return renderAudioDevicesPanel(m.sty, w, true)
	case "audio-output":
		return renderAudioDevicesPanel(m.sty, w, false)
	default:
		return raw
	}
}

// rerenderDynamicPanels walks chat history and regenerates any entry
// tagged with a Kind — i.e. dynamic panels — so they match the current
// terminal width after a resize.
func (m *Model) rerenderDynamicPanels() {
	for peerID, entries := range m.history {
		for i := range entries {
			if entries[i].Kind != "" {
				entries[i].Rendered = m.renderPanel(entries[i].Kind, "")
			}
		}
		m.history[peerID] = entries
	}
	m.refreshChatViewport()
}

func (m *Model) appendEntry(peerID string, e ChatEntry) {
	m.history[peerID] = append(m.history[peerID], e)
	// Cap history to keep memory bounded.
	if len(m.history[peerID]) > 1000 {
		m.history[peerID] = m.history[peerID][len(m.history[peerID])-1000:]
	}
}

func (m *Model) refreshChatViewport() {
	key := ""
	if m.activeChat.String() != "" {
		key = m.activeChat.String()
	}
	entries := m.history[key]
	var b strings.Builder
	// If a video frame is live for this peer, put it above messages.
	if vf, ok := m.videoFrame[key]; ok && vf != "" {
		b.WriteString(m.sty.msgSystem.Render("[video]"))
		b.WriteByte('\n')
		b.WriteString(vf)
		b.WriteString("\n\n")
	}
	for _, e := range entries {
		b.WriteString(e.Rendered)
		b.WriteByte('\n')
	}
	// Empty-state hint
	if b.Len() == 0 {
		if m.activeChat.String() == "" {
			b.WriteString(m.sty.msgSystem.Render("выбери контакт в сайдбаре (Tab, j/k, Enter) или /connect <nick>"))
		} else {
			b.WriteString(m.sty.msgSystem.Render("сообщений пока нет — начни печатать"))
		}
	}
	m.chat.SetContent(b.String())
	m.chat.GotoBottom()
}

func (m *Model) renderChatMessage(msg MsgChatMessage) ChatEntry {
	ts := m.sty.msgTS.Render(msg.Timestamp.Format("15:04:05"))
	name := msg.Nick
	if m.node != nil && msg.PeerID == m.node.GetHostID() {
		name = m.sty.msgOwn.Render(name)
	} else {
		name = m.sty.msgPeer.Render(name)
	}
	line := fmt.Sprintf("%s %s %s", ts, name, msg.Text)
	return ChatEntry{Timestamp: msg.Timestamp, Rendered: line}
}

func (m *Model) setNotice(level, text string) {
	m.lastNotice = text
	m.lastNoticeTS = time.Now()
	m.lastNoticeLvl = level
}

// appendCallLog drops a call-lifecycle log line into BOTH the peer's own
// history lane AND the currently-visible lane (activeChat, or "" for the
// default view). This guarantees the user sees the event regardless of
// which chat — or no chat — they've got open. Dedupes if they're the same.
func (m *Model) appendCallLog(peerID string, rendered string) {
	entry := ChatEntry{Timestamp: time.Now(), Rendered: rendered}
	m.appendEntry(peerID, entry)
	currentKey := m.activeChat.String()
	if currentKey != peerID {
		m.appendEntry(currentKey, entry)
	}
}

func (m *Model) clampSidebar() {
	if m.sidebarIdx >= len(m.contacts) {
		m.sidebarIdx = len(m.contacts) - 1
	}
	if m.sidebarIdx < 0 {
		m.sidebarIdx = 0
	}
}

func (m *Model) selectSidebarByPeer(pid peer.ID) {
	for i, c := range m.contacts {
		if c.PeerID == pid {
			m.sidebarIdx = i
			return
		}
	}
}

func (m *Model) openSelected() {
	if m.sidebarIdx < 0 || m.sidebarIdx >= len(m.contacts) {
		return
	}
	c := m.contacts[m.sidebarIdx]
	m.activeChat = c.PeerID
	m.unread[c.PeerID.String()] = 0
	// If not already in a session, initiate.
	if c.State != f2f.StateActive && c.Stream == nil {
		go m.node.InitConnect(c.Nickname)
	}
	m.refreshChatViewport()
}

// -----------------------------------------------------------------------------
// Commands (tea.Cmd)
// -----------------------------------------------------------------------------

type contactsRefreshedMsg struct{ list []*f2f.Contact }

func refreshContactsCmd(node *f2f.Node) tea.Cmd {
	return func() tea.Msg {
		return contactsRefreshedMsg{list: node.GetContacts()}
	}
}

func tickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg { return MsgTick{} })
}

// -----------------------------------------------------------------------------
// Small helpers
// -----------------------------------------------------------------------------

func humanBytes(b int64) string {
	const (
		k = 1 << 10
		m = 1 << 20
		g = 1 << 30
	)
	switch {
	case b >= g:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(g))
	case b >= m:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(m))
	case b >= k:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(k))
	}
	return fmt.Sprintf("%d B", b)
}
