package f2f

import (
	_ "embed"
	"time"
)

// -----------------------------------------------------------------------------
// Built-in ASCII avatar — used when Settings.VideoSourceType == "ascii".
// The source is aski3.png, pre-rendered to 80×24 chars via cmd/asciigen
// and embedded at compile time. No ffmpeg, no image file at runtime.
// -----------------------------------------------------------------------------

// asciiAvatarFrame is embedded from pkg/f2f/aski.ascii — regenerate with:
//
//	go run ./cmd/asciigen aski3.png > pkg/f2f/aski.ascii
//
//go:embed aski.ascii
var asciiAvatarFrame string

// asciiAvatarSource serves asciiAvatarFrame forever at VideoFPS.
type asciiAvatarSource struct{}

func (asciiAvatarSource) NextFrame() (string, time.Duration, error) {
	return padToResolution(asciiAvatarFrame, VideoCols, VideoRows),
		videoFrameMs * time.Millisecond, nil
}
func (asciiAvatarSource) Close() error { return nil }

// OpenAsciiAvatarSource returns the built-in static placeholder frame.
// Useful when the user has no camera and doesn't want to configure a file.
func OpenAsciiAvatarSource() (VideoSource, error) {
	return asciiAvatarSource{}, nil
}

// padToResolution makes sure the frame is exactly W columns × H rows of
// runes. Trims excess rows/cols, pads short rows with spaces, short frames
// with blank rows. Keeps receiver rendering deterministic.
func padToResolution(frame string, w, h int) string {
	rows := splitRowsLimited(frame, h+1)
	for len(rows) > 0 && rows[0] == "" {
		rows = rows[1:]
	}
	if len(rows) > h {
		rows = rows[:h]
	}
	out := make([]byte, 0, w*h+h)
	for _, r := range rows {
		runes := []rune(r)
		if len(runes) > w {
			runes = runes[:w]
		}
		for _, rn := range runes {
			out = append(out, string(rn)...)
		}
		for pad := w - len(runes); pad > 0; pad-- {
			out = append(out, ' ')
		}
		out = append(out, '\n')
	}
	for added := len(rows); added < h; added++ {
		for i := 0; i < w; i++ {
			out = append(out, ' ')
		}
		out = append(out, '\n')
	}
	return string(out)
}

// splitRowsLimited splits s on '\n' but caps the returned slice length.
func splitRowsLimited(s string, max int) []string {
	rows := make([]string, 0, max)
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			rows = append(rows, s[start:i])
			start = i + 1
			if len(rows) >= max {
				return rows
			}
		}
	}
	if start < len(s) {
		rows = append(rows, s[start:])
	}
	return rows
}
