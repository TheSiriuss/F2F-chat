package main

import (
	"fmt"
	"log"
	"time"

	"github.com/TheSiriuss/F2F-chat/pkg/f2f"
)

// GUIAdapter реализует f2f.UIListener
type GUIAdapter struct {
	state *UIState
}

func (g *GUIAdapter) OnMessage(peerID, nick, text string, t time.Time) {
	g.state.mu.Lock()
	g.state.Messages = append(g.state.Messages, UIMessage{
		Sender: nick,
		Text:   text,
		Time:   t,
	})
	// Автоскролл вниз
	if len(g.state.Messages) > 0 {
		g.state.ListChat.Position.First = len(g.state.Messages) - 1
	}
	g.state.mu.Unlock()
	g.state.Window.Invalidate()
}

func (g *GUIAdapter) OnLog(level, format string, args ...any) {
	msg := fmt.Sprintf("[%s] %s", level, fmt.Sprintf(format, args...))
	log.Println(msg)
}

func (g *GUIAdapter) OnContactUpdate() {
	g.state.Window.Invalidate()
}

func (g *GUIAdapter) OnChatChanged(peerID, nick string) {
	g.state.mu.Lock()
	g.state.Messages = nil
	// Сбрасываем файловое состояние при смене чата
	g.state.FileTransfer = &FileTransferUI{}
	g.state.mu.Unlock()
	g.state.Window.Invalidate()
}

func (g *GUIAdapter) OnFileOffer(peerID, nick, filename string, size int64) {
	g.state.mu.Lock()
	g.state.FileTransfer.HasIncoming = true
	g.state.FileTransfer.IncomingNick = nick
	g.state.FileTransfer.IncomingName = filename
	g.state.FileTransfer.IncomingSize = size
	g.state.mu.Unlock()

	g.OnLog(f2f.LogLevelInfo, "%s предлагает файл: %s (%s)", nick, filename, formatSize(size))
	g.state.Window.Invalidate()
}

func (g *GUIAdapter) OnFileProgress(peerID, nick, filename string, progress float64, isUpload bool) {
	g.state.mu.Lock()
	g.state.FileTransfer.IsActive = true
	g.state.FileTransfer.IsUpload = isUpload
	g.state.FileTransfer.FileName = filename
	g.state.FileTransfer.Progress = progress

	if isUpload {
		g.state.FileTransfer.StatusText = fmt.Sprintf("Отправка: %.0f%%", progress*100)
	} else {
		g.state.FileTransfer.StatusText = fmt.Sprintf("Получение: %.0f%%", progress*100)
	}
	g.state.mu.Unlock()
	g.state.Window.Invalidate()
}

func (g *GUIAdapter) OnFileReceived(peerID, nick, filename, savedPath string, size int64) {
	g.state.mu.Lock()
	// Добавляем сообщение в чат
	g.state.Messages = append(g.state.Messages, UIMessage{
		Sender:   nick,
		Text:     fmt.Sprintf("📁 Файл получен: %s (%s)", filename, formatSize(size)),
		Time:     time.Now(),
		IsFile:   true,
		FileName: savedPath,
	})

	// Сбрасываем состояние передачи
	g.state.FileTransfer.IsActive = false
	g.state.FileTransfer.HasIncoming = false
	g.state.FileTransfer.ShowResult = true
	g.state.FileTransfer.ResultSuccess = true
	g.state.FileTransfer.ResultMessage = fmt.Sprintf("Сохранено: %s", savedPath)
	g.state.FileTransfer.ResultTime = time.Now()
	g.state.mu.Unlock()

	g.OnLog(f2f.LogLevelSuccess, "Файл от %s сохранён: %s", nick, savedPath)
	g.state.Window.Invalidate()
}

func (g *GUIAdapter) OnFileComplete(peerID, nick, filename string, success bool, message string) {
	g.state.mu.Lock()
	g.state.FileTransfer.IsActive = false
	g.state.FileTransfer.HasIncoming = false
	g.state.FileTransfer.ShowResult = true
	g.state.FileTransfer.ResultSuccess = success
	g.state.FileTransfer.ResultMessage = message
	g.state.FileTransfer.ResultTime = time.Now()

	// Добавляем сообщение в чат
	var msgText string
	if success {
		msgText = fmt.Sprintf("✅ Файл '%s': %s", filename, message)
	} else {
		msgText = fmt.Sprintf("❌ Файл '%s': %s", filename, message)
	}
	g.state.Messages = append(g.state.Messages, UIMessage{
		Sender: "System",
		Text:   msgText,
		Time:   time.Now(),
		IsFile: true,
	})
	g.state.mu.Unlock()

	if success {
		g.OnLog(f2f.LogLevelSuccess, "Передача '%s' завершена: %s", filename, message)
	} else {
		g.OnLog(f2f.LogLevelError, "Передача '%s' не удалась: %s", filename, message)
	}
	g.state.Window.Invalidate()
}

// formatSize форматирует размер файла
func formatSize(bytes int64) string {
	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
	)
	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.2f GB", float64(bytes)/GB)
	case bytes >= MB:
		return fmt.Sprintf("%.2f MB", float64(bytes)/MB)
	case bytes >= KB:
		return fmt.Sprintf("%.2f KB", float64(bytes)/KB)
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}
