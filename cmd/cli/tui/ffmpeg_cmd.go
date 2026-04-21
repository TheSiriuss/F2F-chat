package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/TheSiriuss/aski-chat/pkg/aski"
)

// handleFFmpegCmd implements:
//   .ffmpeg          — print status (installed path or "not found")
//   .ffmpeg install  — download & cache ffmpeg (Windows auto-installer;
//                      other OSes print a hint to use the package manager)
func handleFFmpegCmd(node *f2f.Node, args []string) tea.Cmd {
	if len(args) == 0 {
		return funcCmd(func() {
			if p := f2f.ResolveFFmpeg(); p != "" {
				node.Log(f2f.LogLevelSuccess, "ffmpeg найден: %s", p)
			} else {
				node.Log(f2f.LogLevelWarning, "ffmpeg не найден. Запусти .ffmpeg install для автозагрузки")
			}
		})
	}

	sub := strings.ToLower(args[0])
	switch sub {
	case "install", "download", "dl":
		return func() tea.Msg {
			go runFFmpegInstall(node)
			return nil
		}
	default:
		return notice("usage: .ffmpeg [install]")
	}
}

// runFFmpegInstall drives EnsureFFmpeg and surfaces download progress via
// throttled log messages so the user actually sees what's happening.
func runFFmpegInstall(node *f2f.Node) {
	if p := f2f.ResolveFFmpeg(); p != "" {
		node.Log(f2f.LogLevelSuccess, "ffmpeg уже установлен: %s", p)
		return
	}

	node.Log(f2f.LogLevelInfo, "Качаю ffmpeg (один раз, ~80 МБ)...")

	var lastStage string
	var lastEmit time.Time
	progress := func(stage string, done, total int64) {
		// Throttle to 1 update per second per stage.
		if stage != lastStage {
			lastStage = stage
			lastEmit = time.Time{} // force first emit
			node.Log(f2f.LogLevelInfo, "ffmpeg: %s...", stage)
		}
		if time.Since(lastEmit) < time.Second {
			return
		}
		lastEmit = time.Now()
		if total > 0 {
			pct := float64(done) * 100 / float64(total)
			node.Log(f2f.LogLevelInfo, "ffmpeg %s: %.0f%% (%s / %s)",
				stage, pct, humanSize(done), humanSize(total))
		} else {
			node.Log(f2f.LogLevelInfo, "ffmpeg %s: %s", stage, humanSize(done))
		}
	}

	path, err := f2f.EnsureFFmpeg(progress)
	if err != nil {
		node.Log(f2f.LogLevelError, "ffmpeg install: %v", err)
		return
	}
	node.Log(f2f.LogLevelSuccess, "ffmpeg установлен: %s", path)
}

// humanSize formats a byte count as "1.2 MB" / "340 KB" etc.
func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for n2 := n / unit; n2 >= unit; n2 /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}
