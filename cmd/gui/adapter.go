package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
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
	g.state.mu.Unlock()
	g.state.Window.Invalidate()
}

func (g *GUIAdapter) OnFileOffer(peerID, nick, filename string, size int64) {
	g.OnLog(f2f.LogLevelInfo, "%s предлагает файл: %s (%s)", nick, filename, formatSize(size))
	// TODO: показать диалог в GUI
}

func (g *GUIAdapter) OnFileProgress(peerID, nick, filename string, progress float64, isUpload bool) {
	// TODO: показать прогресс-бар в GUI
}

func (g *GUIAdapter) OnFileReceived(peerID, nick, filename, savedPath string, size int64) {
	g.OnLog(f2f.LogLevelSuccess, "Файл от %s сохранён: %s (%s)", nick, savedPath, formatSize(size))
}

func (g *GUIAdapter) OnFileComplete(peerID, nick, filename string, success bool, message string) {
	if success {
		g.OnLog(f2f.LogLevelSuccess, "Передача '%s' завершена: %s", filename, message)
	} else {
		g.OnLog(f2f.LogLevelError, "Передача '%s' не удалась: %s", filename, message)
	}
}

// Legacy метод для совместимости (если где-то используется)
func (g *GUIAdapter) OnFileReceivedLegacy(peerID, nick, filename string, data []byte, timestamp time.Time) {
	g.OnLog(f2f.LogLevelInfo, "Получен файл '%s' от %s (%d bytes)", filename, nick, len(data))

	savePath := filename
	if _, err := os.Stat(savePath); err == nil {
		ext := filepath.Ext(filename)
		base := strings.TrimSuffix(filename, ext)
		savePath = fmt.Sprintf("%s_%s%s", base, timestamp.Format("150405"), ext)
	}

	if err := os.WriteFile(savePath, data, 0644); err != nil {
		g.OnLog(f2f.LogLevelError, "Ошибка сохранения: %v", err)
	}
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