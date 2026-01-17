package f2f

import "time"

// UIListener методы, которые должен реализовать GUI или CLI
type UIListener interface {
	// Сообщение в чат (от кого-то или от себя)
	OnMessage(peerID string, nick string, text string, timestamp time.Time)

	// Системное сообщение (ошибки, инфо)
	OnLog(level string, format string, args ...any)

	// Обновление состояния контактов
	OnContactUpdate()

	// Смена активного чата
	OnChatChanged(peerID string, nick string)
}

const (
	LogLevelInfo    = "INFO"
	LogLevelWarning = "WARN"
	LogLevelError   = "ERR"
	LogLevelSuccess = "OK"
)
