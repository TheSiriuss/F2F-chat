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

const (
	LogLevelInfo    = "INFO"
	LogLevelWarning = "WARN"
	LogLevelError   = "ERR"
	LogLevelSuccess = "OK"
)
