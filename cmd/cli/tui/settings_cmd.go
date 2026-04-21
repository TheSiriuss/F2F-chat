package tui

import (
	"fmt"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/TheSiriuss/aski-chat/pkg/aski"
)

// -----------------------------------------------------------------------------
// .settings — sub-commands for editing user preferences from the TUI.
//
// No modal interactive menu — we reuse the dot-command paradigm so everything
// is discoverable via the autocomplete list and can be scripted if needed.
//
// Usage:
//   .settings                        — show current values (panel)
//   .settings autoplay               — toggle voice auto-play on/off
//   .settings videotype              — cycle auto / camera / file
//   .settings input                  — list input (mic) devices numbered
//   .settings input  <N>             — pick input device #N
//   .settings output                 — list output (speaker) devices numbered
//   .settings output <N>             — pick output device #N
//   .settings camera                 — list cameras numbered (uses ffmpeg)
//   .settings camera <N>             — pick camera #N (0 = default)
//   .settings file   <path>          — set video stub file (empty path clears)
//   .settings file   clear           — clear video stub file
// -----------------------------------------------------------------------------

func handleSettingsCmd(args []string) tea.Cmd {
	if len(args) == 0 {
		return func() tea.Msg { return MsgSystemPanel{Kind: "settings"} }
	}

	sub := strings.ToLower(args[0])
	rest := args[1:]

	switch sub {
	case "autoplay":
		return funcCmd(func() {
			s := f2f.LoadSettings()
			s.VoiceAutoPlay = !s.VoiceAutoPlay
			_ = f2f.SaveSettings(s)
		})

	case "input":
		return handleAudioPick(rest, true)
	case "output":
		return handleAudioPick(rest, false)

	case "camera":
		return handleCameraPick(rest)

	case "file":
		if len(rest) == 0 {
			return notice("usage: .settings file <path> | .settings file clear")
		}
		arg := strings.Join(rest, " ")
		return funcCmd(func() {
			s := f2f.LoadSettings()
			if strings.EqualFold(arg, "clear") {
				s.VideoSourcePath = ""
			} else {
				s.VideoSourcePath = arg
			}
			_ = f2f.SaveSettings(s)
		})

	default:
		return notice(fmt.Sprintf("неизвестный раздел: %s (см. .settings без аргументов)", sub))
	}
}

// handleAudioPick either lists audio devices (no args) or selects one by index.
func handleAudioPick(rest []string, wantInput bool) tea.Cmd {
	kind := "input"
	if !wantInput {
		kind = "output"
	}

	if len(rest) == 0 {
		// Emit a panel that enumerates the devices.
		k := "audio-input"
		if !wantInput {
			k = "audio-output"
		}
		return func() tea.Msg { return MsgSystemPanel{Kind: k} }
	}

	n, err := strconv.Atoi(strings.TrimSpace(rest[0]))
	if err != nil {
		return notice(fmt.Sprintf("usage: .settings %s <номер> (см. .settings %s)", kind, kind))
	}

	return func() tea.Msg {
		devices, err := f2f.ListAudioDevices()
		if err != nil {
			return MsgLog{Level: f2f.LogLevelError, Format: "Не могу получить список устройств: " + err.Error()}
		}
		var filtered []f2f.AudioDevice
		for _, d := range devices {
			if d.IsInput == wantInput {
				filtered = append(filtered, d)
			}
		}
		s := f2f.LoadSettings()
		if n == 0 {
			if wantInput {
				s.AudioInputDeviceID = ""
				s.AudioInputDeviceName = ""
			} else {
				s.AudioOutputDeviceID = ""
				s.AudioOutputDeviceName = ""
			}
			if err := f2f.SaveSettings(s); err != nil {
				return MsgLog{Level: f2f.LogLevelError, Format: "Сохранение: " + err.Error()}
			}
			return MsgLog{Level: f2f.LogLevelSuccess, Format: "[OK] " + kind + ": по умолчанию"}
		}
		if n < 1 || n > len(filtered) {
			return MsgLog{Level: f2f.LogLevelWarning, Format: fmt.Sprintf("вне диапазона (1..%d, 0=default)", len(filtered))}
		}
		d := filtered[n-1]
		if wantInput {
			s.AudioInputDeviceID = d.ID
			s.AudioInputDeviceName = d.Name
		} else {
			s.AudioOutputDeviceID = d.ID
			s.AudioOutputDeviceName = d.Name
		}
		if err := f2f.SaveSettings(s); err != nil {
			return MsgLog{Level: f2f.LogLevelError, Format: "Сохранение: " + err.Error()}
		}
		return MsgLog{Level: f2f.LogLevelSuccess, Format: "[OK] " + kind + ": " + d.Name}
	}
}

// handleCameraPick either lists cameras (no args) or picks one by index.
//
// Index 0 is the built-in ASCII avatar — it's the no-camera default and
// works without ffmpeg/webcam. 1..N are real cameras enumerated via ffmpeg.
func handleCameraPick(rest []string) tea.Cmd {
	if len(rest) == 0 {
		return func() tea.Msg { return MsgSystemPanel{Kind: "cameras"} }
	}
	n, err := strconv.Atoi(strings.TrimSpace(rest[0]))
	if err != nil {
		return notice("usage: .settings camera <номер> (см. .settings camera)")
	}
	return func() tea.Msg {
		s := f2f.LoadSettings()

		// 0 = ASCII avatar. No ffmpeg required.
		if n == 0 {
			s.VideoSourceType = "ascii"
			s.VideoCameraID = ""
			if err := f2f.SaveSettings(s); err != nil {
				return MsgLog{Level: f2f.LogLevelError, Format: "Сохранение: " + err.Error()}
			}
			return MsgLog{Level: f2f.LogLevelSuccess, Format: "[OK] источник видео: ASCII-аватар (камера не используется)"}
		}

		// 1..N = real cameras. Needs ffmpeg to enumerate / run.
		if !f2f.CameraAvailable() {
			return MsgLog{Level: f2f.LogLevelError, Format: "ffmpeg не установлен (.ffmpeg install)"}
		}
		cams, _, err := f2f.ListCamerasVerbose()
		if err != nil {
			return MsgLog{Level: f2f.LogLevelError, Format: "Список камер: " + err.Error()}
		}
		if n < 1 || n > len(cams) {
			return MsgLog{Level: f2f.LogLevelWarning, Format: fmt.Sprintf("вне диапазона (1..%d, 0=ASCII-аватар)", len(cams))}
		}
		s.VideoSourceType = "camera"
		s.VideoCameraID = cams[n-1]
		if err := f2f.SaveSettings(s); err != nil {
			return MsgLog{Level: f2f.LogLevelError, Format: "Сохранение: " + err.Error()}
		}
		return MsgLog{Level: f2f.LogLevelSuccess, Format: "[OK] камера: " + cams[n-1]}
	}
}
