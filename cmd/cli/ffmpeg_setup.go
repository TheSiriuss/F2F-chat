package main

import (
	"fmt"

	"github.com/TheSiriuss/aski/pkg/aski"
)

// ensureFFmpegInstalled checks for ffmpeg and, if missing, downloads it
// (Windows only). Prints a simple progress indicator to the console.
// Returns true if an ffmpeg is now available.
func ensureFFmpegInstalled(ui *ConsoleAdapter) bool {
	if f2f.ResolveFFmpeg() != "" {
		return true
	}

	ui.OnLog(f2f.LogLevelInfo, "ffmpeg не найден, скачиваю в кэш (~130 МБ, один раз)…")
	var lastPct int
	progress := func(stage string, done, total int64) {
		if total <= 0 {
			return
		}
		pct := int(done * 100 / total)
		// Avoid spamming the same percent.
		if pct == lastPct {
			return
		}
		lastPct = pct
		// Print on a single line — \r keeps us on the same row.
		fmt.Printf("\r  %s: %3d%% (%.1f / %.1f МБ)     ",
			stage, pct,
			float64(done)/1024/1024,
			float64(total)/1024/1024)
	}

	path, err := f2f.EnsureFFmpeg(progress)
	fmt.Println()
	if err != nil {
		ui.OnLog(f2f.LogLevelError, "Установка ffmpeg провалилась: %v", err)
		return false
	}
	ui.OnLog(f2f.LogLevelSuccess, "ffmpeg готов: %s", path)
	return true
}
