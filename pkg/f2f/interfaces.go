package f2f

import "time"

// UIListener методы, которые должен реализовать GUI или CLI
type UIListener interface {
	// Сообщение в чат
	OnMessage(peerID string, nick string, text string, timestamp time.Time)

	// Предложение файла (получатель должен принять/отклонить)
	OnFileOffer(peerID string, nick string, filename string, size int64)

	// Прогресс передачи файла (0.0 - 1.0)
	OnFileProgress(peerID string, nick string, filename string, progress float64, isUpload bool)

	// Файл успешно получен и сохранён
	OnFileReceived(peerID string, nick string, filename string, savedPath string, size int64)

	// Передача завершена (успех или ошибка)
	OnFileComplete(peerID string, nick string, filename string, success bool, message string)

	// Системное сообщение
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
