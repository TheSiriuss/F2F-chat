package tui

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// -----------------------------------------------------------------------------
// Adapter: bridges f2f.Node's callback-based UIListener interface to the
// bubbletea message bus. All incoming events (message, file offer, call,
// log line…) are turned into tea.Msg values and injected via Program.Send,
// which is the bubbletea-sanctioned way to deliver async updates to the
// Model.Update loop.
// -----------------------------------------------------------------------------

type Adapter struct {
	prog *tea.Program
}

func NewAdapter() *Adapter { return &Adapter{} }

// Attach wires the adapter to a running bubbletea program. Must be called
// before any listener method fires (i.e. before f2f.NewNode starts its
// background goroutines), otherwise early events get silently dropped.
func (a *Adapter) Attach(p *tea.Program) { a.prog = p }

func (a *Adapter) send(m tea.Msg) {
	if a.prog != nil {
		a.prog.Send(m)
	}
}

// -----------------------------------------------------------------------------
// tea.Msg types corresponding to UIListener callbacks
// -----------------------------------------------------------------------------

type (
	MsgChatMessage struct {
		PeerID    string
		Nick      string
		Text      string
		Timestamp time.Time
	}
	MsgFileOffer struct {
		PeerID   string
		Nick     string
		Filename string
		Size     int64
	}
	MsgFileProgress struct {
		PeerID   string
		Nick     string
		Filename string
		Progress float64
		IsUpload bool
	}
	MsgFileReceived struct {
		PeerID    string
		Nick      string
		Filename  string
		SavedPath string
		Size      int64
	}
	MsgFileComplete struct {
		PeerID   string
		Nick     string
		Filename string
		Success  bool
		Message  string
	}
	MsgLog struct {
		Level  string
		Format string
		Args   []any
	}
	MsgContactUpdate struct{}
	MsgChatChanged   struct {
		PeerID string
		Nick   string
	}
	MsgVideoFrame struct {
		PeerID string
		Nick   string
		Frame  string
	}
	// Call lifecycle events — emitted independently of OnLog so the UI can
	// render a prominent banner in the contact's own history lane instead
	// of relying on a fleeting notice.
	MsgCallIncoming struct {
		PeerID string
		Nick   string
		Kind   string // "voice" or "video"
	}
	MsgCallOutgoing struct {
		PeerID string
		Nick   string
		Kind   string
	}
	MsgCallActive struct {
		PeerID string
		Nick   string
		Kind   string
	}
	MsgCallEnded struct {
		PeerID   string
		Nick     string
		Reason   string
		Duration string
	}

	// Cosmetic / animation ticks
	MsgTick struct{}

	// MsgSystemPanel requests the Update loop to render one of the
	// built-in panels ("info" / "contacts" / "fingerprint" / "welcome")
	// using the CURRENT chat-pane width, then append it to history. This
	// avoids the palette commands from having to know the layout size.
	//
	// If Kind is empty, Raw is used verbatim as the rendered content.
	MsgSystemPanel struct {
		PeerID string // empty = global system lane
		Kind   string // "info" / "contacts" / "fingerprint" / "welcome" / ""
		Raw    string // used when Kind == ""
	}
)

// -----------------------------------------------------------------------------
// UIListener implementation — thin, just forwards into the tea program.
// -----------------------------------------------------------------------------

func (a *Adapter) OnMessage(pid, nick, text string, ts time.Time) {
	a.send(MsgChatMessage{pid, nick, text, ts})
}
func (a *Adapter) OnFileOffer(pid, nick, filename string, size int64) {
	a.send(MsgFileOffer{pid, nick, filename, size})
}
func (a *Adapter) OnFileProgress(pid, nick, filename string, progress float64, isUpload bool) {
	a.send(MsgFileProgress{pid, nick, filename, progress, isUpload})
}
func (a *Adapter) OnFileReceived(pid, nick, filename, savedPath string, size int64) {
	a.send(MsgFileReceived{pid, nick, filename, savedPath, size})
}
func (a *Adapter) OnFileComplete(pid, nick, filename string, success bool, message string) {
	a.send(MsgFileComplete{pid, nick, filename, success, message})
}
func (a *Adapter) OnLog(level, format string, args ...any) {
	a.send(MsgLog{level, format, args})
}
func (a *Adapter) OnContactUpdate() {
	a.send(MsgContactUpdate{})
}
func (a *Adapter) OnChatChanged(pid, nick string) {
	a.send(MsgChatChanged{pid, nick})
}
func (a *Adapter) OnVideoFrame(pid, nick, frame string) {
	a.send(MsgVideoFrame{pid, nick, frame})
}
func (a *Adapter) OnCallIncoming(pid, nick, kind string) {
	a.send(MsgCallIncoming{pid, nick, kind})
}
func (a *Adapter) OnCallOutgoing(pid, nick, kind string) {
	a.send(MsgCallOutgoing{pid, nick, kind})
}
func (a *Adapter) OnCallActive(pid, nick, kind string) {
	a.send(MsgCallActive{pid, nick, kind})
}
func (a *Adapter) OnCallEnded(pid, nick, reason, duration string) {
	a.send(MsgCallEnded{pid, nick, reason, duration})
}
