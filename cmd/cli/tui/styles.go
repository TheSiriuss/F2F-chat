package tui

import "github.com/charmbracelet/lipgloss"

// -----------------------------------------------------------------------------
// Style palette — deliberately minimal, semantic colors.
// -----------------------------------------------------------------------------

var (
	// Brand / accents
	colAccent   = lipgloss.Color("#7D56F4") // purple — app highlight
	colOnline   = lipgloss.Color("#5EC572") // green
	colOffline  = lipgloss.Color("#606060") // grey
	colInChat   = lipgloss.Color("#3B9EFF") // blue
	colError    = lipgloss.Color("#E94E4E")
	colWarn     = lipgloss.Color("#F4B942")
	colMuted    = lipgloss.Color("#808080")
	colSubtle   = lipgloss.Color("#A0A0A0")
	colSelfMsg  = lipgloss.Color("#9FB7E6")
	colPeerName = lipgloss.Color("#5EC572")
	colPrompt   = lipgloss.Color("#7D56F4")
	colBorder   = lipgloss.Color("#3A3A3A")
)

type styles struct {
	header    lipgloss.Style
	headerBar lipgloss.Style

	sidebar       lipgloss.Style
	sidebarTitle  lipgloss.Style
	contact       lipgloss.Style
	contactActive lipgloss.Style
	badgeChat     lipgloss.Style
	badgeUnread   lipgloss.Style

	chatPane     lipgloss.Style
	chatHeader   lipgloss.Style
	msgOwn       lipgloss.Style
	msgPeer      lipgloss.Style
	msgTS        lipgloss.Style
	msgSystem    lipgloss.Style
	msgErr       lipgloss.Style
	msgOK        lipgloss.Style
	msgWarn      lipgloss.Style

	input       lipgloss.Style
	inputPrompt lipgloss.Style

	footer     lipgloss.Style
	helpKey    lipgloss.Style
	helpText   lipgloss.Style

	overlay       lipgloss.Style
	overlayTitle  lipgloss.Style
	callBar       lipgloss.Style
	paletteMatch  lipgloss.Style
	paletteHit    lipgloss.Style
}

func newStyles() styles {
	s := styles{}
	s.header = lipgloss.NewStyle().Bold(true).Foreground(colAccent)
	s.headerBar = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#EEEEEE")).
		Padding(0, 1)

	s.sidebar = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder(), false, true, false, false).
		BorderForeground(colBorder).
		Padding(0, 1)
	s.sidebarTitle = lipgloss.NewStyle().Bold(true).Foreground(colMuted).Padding(0, 0, 1, 0)

	s.contact = lipgloss.NewStyle().Padding(0, 0)
	s.contactActive = lipgloss.NewStyle().Bold(true).
		Foreground(lipgloss.Color("#FFFFFF")).
		Background(colAccent).
		Padding(0, 1)

	s.badgeChat = lipgloss.NewStyle().Foreground(colInChat).Italic(true)
	s.badgeUnread = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#FFFFFF")).
		Background(colError).
		Padding(0, 1)

	s.chatPane = lipgloss.NewStyle().Padding(0, 1)
	s.chatHeader = lipgloss.NewStyle().Bold(true).
		Foreground(colAccent).
		Border(lipgloss.NormalBorder(), false, false, true, false).
		BorderForeground(colBorder).
		Padding(0, 0, 0, 0)

	s.msgTS = lipgloss.NewStyle().Foreground(colMuted)
	s.msgOwn = lipgloss.NewStyle().Foreground(colSelfMsg)
	s.msgPeer = lipgloss.NewStyle().Foreground(colPeerName).Bold(true)
	s.msgSystem = lipgloss.NewStyle().Foreground(colMuted).Italic(true)
	s.msgErr = lipgloss.NewStyle().Foreground(colError)
	s.msgOK = lipgloss.NewStyle().Foreground(colOnline)
	s.msgWarn = lipgloss.NewStyle().Foreground(colWarn)

	s.input = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder(), true, false, false, false).
		BorderForeground(colBorder).
		Padding(0, 1)
	s.inputPrompt = lipgloss.NewStyle().Foreground(colPrompt).Bold(true)

	s.footer = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#AAAAAA")).
		Padding(0, 1)
	s.helpKey = lipgloss.NewStyle().Foreground(colAccent).Bold(true)
	s.helpText = lipgloss.NewStyle().Foreground(colSubtle)

	s.overlay = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(colAccent).
		Padding(1, 2)
	s.overlayTitle = lipgloss.NewStyle().Bold(true).Foreground(colAccent)
	s.callBar = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#FFFFFF")).
		Background(colOnline).
		Bold(true).
		Padding(0, 2)
	s.paletteMatch = lipgloss.NewStyle().Foreground(lipgloss.Color("#E0E0E0"))
	s.paletteHit = lipgloss.NewStyle().Foreground(colAccent).Bold(true)
	return s
}
