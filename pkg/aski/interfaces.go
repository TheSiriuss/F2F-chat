package f2f

import "time"

// UIListener методы, которые должен реализовать GUI или CLI
type UIListener interface {
	OnMessage(peerID string, nick string, text string, timestamp time.Time)
	OnFileOffer(peerID string, nick string, filename string, size int64)
	OnFileProgress(peerID string, nick string, filename string, progress float64, isUpload bool)
	OnFileReceived(peerID string, nick string, filename string, savedPath string, size int64)
	OnFileComplete(peerID string, nick string, filename string, success bool, message string)
	OnLog(level string, format string, args ...any)
	OnContactUpdate()
	OnChatChanged(peerID string, nick string)
}

// CallListener is an optional interface a UIListener may implement to get
// per-peer call lifecycle events. Falls back to OnLog-only if absent, so
// breaking existing implementations is opt-in.
//
// `kind` is "voice" or "video" — UI uses it to distinguish the prompt.
type CallListener interface {
	OnCallIncoming(peerID, nick, kind string)
	OnCallOutgoing(peerID, nick, kind string)
	OnCallActive(peerID, nick, kind string)
	OnCallEnded(peerID, nick, reason, duration string)
}

const (
	LogLevelInfo    = "INFO"
	LogLevelWarning = "WARN"
	LogLevelError   = "ERR"
	LogLevelSuccess = "OK"
)
