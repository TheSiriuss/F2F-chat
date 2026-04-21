package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/TheSiriuss/aski-chat/pkg/aski"
)

func (m Model) View() string {
	if m.width == 0 || m.height == 0 {
		return "loading..."
	}

	header := m.viewHeader()
	input := m.viewInput()
	footer := m.viewFooter()

	// Active call takes over the main pane — chat is hidden until hangup.
	// Video: show incoming ASCII frames. Voice: show a dark placeholder.
	var body string
	if m.activeCall != nil {
		body = m.viewCall()
	} else {
		body = m.viewChat()
	}

	// When a dot-command is being typed, render an IDE-style suggestion
	// list stacked between the main body and the input line.
	suggestions := m.viewSuggestions()

	pieces := []string{header, body}
	if suggestions != "" {
		pieces = append(pieces, suggestions)
	}
	pieces = append(pieces, input, footer)

	frame := lipgloss.JoinVertical(lipgloss.Left, pieces...)

	if m.focus == focusHelp {
		return m.overlayHelp(frame)
	}
	return frame
}

// -----------------------------------------------------------------------------
// Header
// -----------------------------------------------------------------------------

func (m Model) viewHeader() string {
	nick := ""
	if m.node != nil {
		nick = m.node.GetNickname()
	}
	if nick == "" {
		nick = "(не залогинен)"
	}
	relay := "relay: —"
	if m.hasRelay {
		relay = "relay: on"
	}
	// Lead with an unstyled space before the bold brand — some terminals
	// silently eat the first char of a run that starts inside an ANSI
	// colour escape, causing "ASKI CHAT" to render as "SKI CHAT".
	left := " " + m.sty.header.Render("ASKI CHAT") + "  "
	center := fmt.Sprintf("%s • DHT peers: %d • %s", nick, m.dhtPeers, relay)

	// Notice blinks on the right for a few seconds.
	right := ""
	if m.lastNotice != "" {
		st := m.sty.msgSystem
		switch m.lastNoticeLvl {
		case f2f.LogLevelError:
			st = m.sty.msgErr
		case f2f.LogLevelWarning:
			st = m.sty.msgWarn
		case f2f.LogLevelSuccess:
			st = m.sty.msgOK
		}
		right = st.Render(m.lastNotice)
	}

	// Manually pad so left + center is left-aligned, right is right-aligned.
	pad := m.width - lipgloss.Width(left) - lipgloss.Width(center) - lipgloss.Width(right) - 4
	if pad < 1 {
		pad = 1
	}
	// headerBar has Padding(0, 1) — 2 cols outside Width.
	w := m.width - 2
	if w < 10 {
		w = 10
	}
	return m.sty.headerBar.Width(w).Render(
		left + center + strings.Repeat(" ", pad) + right,
	)
}

// -----------------------------------------------------------------------------
// Sidebar
// -----------------------------------------------------------------------------

// sidebarWidth is zero — we no longer render a sidebar. Kept as a function
// so callers (resize, chat-width math) don't need conditionals. If we ever
// bring the sidebar back, switch this to return the computed width.
func (m Model) sidebarWidth() int { return 0 }

func (m Model) viewSidebar() string {
	w := m.sidebarWidth()
	// Calculate the same chat-body height as in resize().
	h := m.height - 5

	var b strings.Builder
	b.WriteString(m.sty.sidebarTitle.Render("КОНТАКТЫ"))
	b.WriteByte('\n')

	if len(m.contacts) == 0 {
		b.WriteString(m.sty.msgSystem.Render("пусто"))
		b.WriteByte('\n')
		b.WriteString(m.sty.msgSystem.Render("/addfriend"))
	}

	// How many characters of the name fit after the icon+padding.
	nameBudget := w - 6
	if nameBudget < 8 {
		nameBudget = 8
	}

	for i, c := range m.contacts {
		icon, _ := contactIcon(c)
		line := fmt.Sprintf("%s %s", icon, truncate(c.Nickname, nameBudget))

		if u := m.unread[c.PeerID.String()]; u > 0 {
			line += " " + m.sty.badgeUnread.Render(fmt.Sprintf("%d", u))
		}
		if c.State == f2f.StateActive && c.PeerID != m.activeChat {
			line += " " + m.sty.badgeChat.Render("chat")
		}

		// Highlight selection based on focus vs active.
		if m.focus == focusSidebar && i == m.sidebarIdx {
			line = m.sty.contactActive.Width(w - 2).Render(line)
		} else if c.PeerID == m.activeChat {
			line = m.sty.contactActive.Width(w - 2).Render(line)
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}

	return m.sty.sidebar.Width(w).Height(h).Render(b.String())
}

func contactIcon(c *f2f.Contact) (string, string) {
	// A recent failed .connect matters more than DHT presence — an
	// "online" contact we can't reach is worse than honestly offline.
	// Window: 2 minutes since the failure was recorded.
	recentFail := !c.LastConnectFailAt.IsZero() &&
		time.Since(c.LastConnectFailAt) < 2*time.Minute

	switch {
	case c.State == f2f.StateActive:
		return lipgloss.NewStyle().Foreground(colInChat).Render("*"), tr("status.inchat")
	case c.Stream != nil:
		return lipgloss.NewStyle().Foreground(colInChat).Render("~"), tr("status.connected")
	case c.State == f2f.StatePendingIncoming:
		return lipgloss.NewStyle().Foreground(colWarn).Render("!"), tr("status.incoming")
	case recentFail:
		return lipgloss.NewStyle().Foreground(colError).Render("x"), tr("status.nochannel")
	case c.Presence == f2f.PresenceOnline:
		return lipgloss.NewStyle().Foreground(colOnline).Render("*"), tr("status.online")
	default:
		return lipgloss.NewStyle().Foreground(colOffline).Render("o"), tr("status.offline")
	}
}

// -----------------------------------------------------------------------------
// Chat pane
// -----------------------------------------------------------------------------

func (m Model) viewChat() string {
	// Header with active contact + status
	var title string
	if m.activeChat.String() != "" {
		nick := "?"
		for _, c := range m.contacts {
			if c.PeerID == m.activeChat {
				nick = c.Nickname
				break
			}
		}
		title = m.sty.chatHeader.Render(nick)
	} else {
		title = m.sty.chatHeader.Render("ASKI CHAT")
	}

	// NOTE: no wrapping style here. Viewport and panels inside already
	// produce exactly the right number of columns (m.chat.Width). Wrapping
	// in a padded container would shrink the effective width and cause
	// border characters of inner panels to overflow / truncate.
	return title + "\n" + m.chat.View()
}

// -----------------------------------------------------------------------------
// Call pane — replaces the chat pane while a call is active
// -----------------------------------------------------------------------------

// viewCall renders the dedicated call UI:
//   - video call: most recent ASCII frame from the peer (or placeholder)
//   - voice call: dark "on air" screen with elapsed time
//   - always: a hint line with .hangup and related commands
func (m Model) viewCall() string {
	call := m.activeCall
	kindLabel := "ГОЛОСОВОЙ ВЫЗОВ"
	if call.Kind == "video" {
		kindLabel = "ВИДЕО ВЫЗОВ"
	}
	elapsed := time.Since(call.Started).Round(time.Second)
	title := m.sty.chatHeader.Render(fmt.Sprintf("%s • %s • %s", kindLabel, call.Nick, elapsed))

	// Inner canvas height = total - (header + input + footer + suggestions).
	// chat.Height is already computed in resize() for the chat pane; reuse it.
	canvasW := m.chat.Width
	canvasH := m.chat.Height
	if canvasW < 20 {
		canvasW = 20
	}
	if canvasH < 6 {
		canvasH = 6
	}

	var content string
	if call.Kind == "video" {
		frame := m.videoFrame[call.PeerID]
		if frame == "" {
			content = renderCallPlaceholder(m.sty, canvasW, canvasH,
				"ожидаю видео от "+call.Nick+"...",
				".hangup чтобы завершить")
		} else {
			content = lipgloss.Place(canvasW, canvasH, lipgloss.Center, lipgloss.Center,
				frame)
		}
	} else {
		content = renderCallPlaceholder(m.sty, canvasW, canvasH,
			"голосовая связь с "+call.Nick,
			".hangup чтобы завершить")
	}
	return title + "\n" + content
}

// renderCallPlaceholder returns a dark canvas of the given dimensions
// with a centered multi-line message — used when no video is available
// (voice-only call or video hasn't arrived yet).
func renderCallPlaceholder(sty styles, w, h int, lines ...string) string {
	inner := make([]string, 0, len(lines))
	for i, l := range lines {
		if i == 0 {
			inner = append(inner, sty.msgOwn.Render(l))
		} else {
			inner = append(inner, sty.msgSystem.Render(l))
		}
	}
	return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center,
		strings.Join(inner, "\n"))
}

// -----------------------------------------------------------------------------
// Input
// -----------------------------------------------------------------------------

func (m Model) viewInput() string {
	prompt := m.sty.inputPrompt.Render("> ")
	line := prompt + m.input.View()
	// input style has Padding(0, 1) left/right = 2 extra columns.
	w := m.width - 2
	if w < 10 {
		w = 10
	}
	return m.sty.input.Width(w).Render(line)
}

// -----------------------------------------------------------------------------
// Footer shortcuts
// -----------------------------------------------------------------------------

func (m Model) viewFooter() string {
	parts := []string{
		m.sty.helpKey.Render(".") + " " + m.sty.helpText.Render(tr("footer.commands")),
		m.sty.helpKey.Render("Tab") + " " + m.sty.helpText.Render(tr("footer.tab")),
		m.sty.helpKey.Render("?") + " " + m.sty.helpText.Render(tr("footer.help")),
		m.sty.helpKey.Render("^C") + " " + m.sty.helpText.Render(tr("footer.quit")),
	}
	line := strings.Join(parts, "  •  ")
	// footer has Padding(0, 1) — 2 cols outside Width.
	w := m.width - 2
	if w < 10 {
		w = 10
	}
	return m.sty.footer.Width(w).Render(line)
}

// -----------------------------------------------------------------------------
// Overlays
// -----------------------------------------------------------------------------

func (m Model) overlayHelp(bg string) string {
	content := []string{
		m.sty.overlayTitle.Render(tr("help.title")),
		"",
		kv(m.sty, ".", tr("help.dot")),
		kv(m.sty, "Up/Down", tr("help.updown")),
		kv(m.sty, "Tab", tr("help.tab")),
		kv(m.sty, "Enter", tr("help.enter")),
		kv(m.sty, "PgUp / PgDn", tr("help.pgudn")),
		kv(m.sty, "Esc", tr("help.esc")),
		kv(m.sty, "?", tr("help.qmark")),
		kv(m.sty, "Ctrl+C", tr("help.ctrlc")),
		"",
		m.sty.overlayTitle.Render(tr("help.cmds")),
		kv(m.sty, ".info / .fingerprint / .copy", tr("help.info_grp")),
		kv(m.sty, ".list / .find", tr("help.list_grp")),
		kv(m.sty, ".addfriend [nick] [peerID] [pub]", tr("help.add_grp")),
		kv(m.sty, ".connect [nick]", tr("help.conn_grp")),
		kv(m.sty, ".accept / .decline / .leave", tr("help.ctrl_grp")),
		kv(m.sty, ".call / .vidcall", tr("help.call_grp")),
		kv(m.sty, ".acceptcall / .hangup", tr("help.accept_grp")),
		kv(m.sty, ".video / .stopvideo", tr("help.video_grp")),
		kv(m.sty, ".file [path]", tr("help.file_grp")),
		kv(m.sty, ".rec / .play", tr("help.rec_grp")),
		kv(m.sty, ".settings / .cameras / .ffmpeg", tr("help.setup_grp")),
		kv(m.sty, ".bootstrap", tr("help.boot_grp")),
		kv(m.sty, ".language [en|ru|de|fr|zh|ja]", "UI language"),
		"",
		m.sty.msgSystem.Render(tr("help.any_key")),
	}
	overlay := m.sty.overlay.Render(strings.Join(content, "\n"))
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, overlay,
		lipgloss.WithWhitespaceChars(" "))
}

// viewSuggestions renders the IDE-style autocomplete list that appears just
// above the input when the user is typing a dot-command. Empty string if
// no suggestions are active.
func (m Model) viewSuggestions() string {
	if !m.isDotCommand() || len(m.suggestions) == 0 {
		return ""
	}

	// Column widths: name + usage can be up to ~40 chars; description takes
	// whatever's left.
	nameColW := 16
	usageColW := 30
	descColW := m.width - nameColW - usageColW - 8 // borders + padding
	if descColW < 20 {
		descColW = 20
	}

	// Scrollable window: render at most `windowSize` items with
	// suggestIdx kept inside the visible range.
	const windowSize = 8
	total := len(m.suggestions)
	start := 0
	if total > windowSize {
		start = m.suggestIdx - windowSize/2
		if start < 0 {
			start = 0
		}
		if start+windowSize > total {
			start = total - windowSize
		}
	}
	end := start + windowSize
	if end > total {
		end = total
	}

	var rows []string
	for i := start; i < end; i++ {
		c := m.suggestions[i]
		name := "." + c.Name
		usage := c.Usage
		desc := c.Desc

		row := fmt.Sprintf("%s %s %s",
			pad(name, nameColW),
			pad(usage, usageColW),
			truncate(desc, descColW))

		if i == m.suggestIdx {
			row = m.sty.paletteHit.Render("> "+row) + ""
		} else {
			row = m.sty.paletteMatch.Render("  " + row)
		}
		rows = append(rows, row)
	}

	// Show position marker if there are hidden items above/below.
	scrollHint := ""
	if total > windowSize {
		scrollHint = fmt.Sprintf("  (%d/%d)", m.suggestIdx+1, total)
	}
	hint := m.sty.msgSystem.Render(tr("suggest.hint") + scrollHint)
	rows = append(rows, hint)

	// Width(m.width - 2) accounts for left+right Padding(0, 1); there's
	// no left/right border on this panel (only top), so no border offset.
	w := m.width - 2
	if w < 20 {
		w = 20
	}
	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder(), true, false, false, false).
		BorderForeground(colBorder).
		Padding(0, 1).
		Width(w).
		Render(strings.Join(rows, "\n"))
}

// kv renders a "key — description" row for the help overlay.
func kv(s styles, key, desc string) string {
	return s.helpKey.Render(pad(key, 28)) + s.helpText.Render(desc)
}

func pad(s string, w int) string {
	if lipgloss.Width(s) >= w {
		return s + " "
	}
	return s + strings.Repeat(" ", w-lipgloss.Width(s))
}

func truncate(s string, w int) string {
	if len([]rune(s)) <= w {
		return s
	}
	r := []rune(s)
	return string(r[:w-1]) + "…"
}

// absorb unused-import warning (time used in refreshed header ts).
var _ = time.Now
