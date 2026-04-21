package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/TheSiriuss/aski/pkg/aski"
	"github.com/chzyer/readline"
)

// dumpFFmpegOutput prints up to ~40 lines of ffmpeg stderr to the console
// with a subtle indent, so the user can see the raw diagnostic.
func dumpFFmpegOutput(ui *ConsoleAdapter, raw string) {
	lines := strings.Split(raw, "\n")
	max := 40
	if len(lines) > max {
		lines = lines[:max]
		lines = append(lines, "  ... (обрезано)")
	}
	for _, l := range lines {
		l = strings.TrimRight(l, "\r\n ")
		if l == "" {
			continue
		}
		fmt.Printf("  │ %s\n", l)
	}
}

// waitAnyKey blocks until the user hits Enter, using the shared readline
// instance. Used as a "press Enter to continue" after error output that
// would otherwise be scrolled past by the settings menu redraw.
func waitAnyKey(rl *readline.Instance, prompt string) {
	rl.SetPrompt(prompt + "> ")
	_, _ = rl.Readline()
	rl.SetPrompt("> ")
}

// autoStartVideoOnAccept polls the outgoing call's state for up to the
// call-offer timeout; once the call becomes Active (callee accepted),
// it triggers StartVideoFrom with the default source. Used by the
// convenience `.videocall` command to fuse voice-call + video into one
// user gesture.
func autoStartVideoOnAccept(node *f2f.Node, ui *ConsoleAdapter, nick string) {
	deadline := time.Now().Add(f2f.CallOfferTimeout)
	for time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
		for _, c := range node.GetContacts() {
			if c.Nickname != nick {
				continue
			}
			call := c.Call
			if call == nil {
				continue
			}
			switch call.State {
			case f2f.CallActive:
				if err := node.StartVideoFrom(nick, ""); err != nil {
					ui.OnLog(f2f.LogLevelError, "Автостарт видео: %v", err)
				}
				return
			case f2f.CallIdle:
				// Call ended before being accepted — nothing to do.
				return
			}
		}
	}
}

// pickCallTarget resolves which contact a call command applies to.
//  - If an explicit nick was given, use it.
//  - If wantIncoming is true (accept/decline), find the unique contact
//    that has an Incoming call pending; error if 0 or >1.
//  - Otherwise (voicecall/hangup) fall back to the active chat partner,
//    or the unique contact with any ongoing Call.
func pickCallTarget(node *f2f.Node, parts []string, wantIncoming bool) string {
	if len(parts) > 1 {
		return parts[1]
	}

	contacts := node.GetContacts()
	var matches []string
	for _, c := range contacts {
		// Racy read is OK here — we just want a "good enough" snapshot for
		// UX routing; the real call API re-checks under lock.
		call := c.Call
		if call == nil {
			continue
		}
		if wantIncoming {
			if call.State == f2f.CallIncoming {
				matches = append(matches, c.Nickname)
			}
		} else {
			// Any call state counts for .voicecall (to re-initiate) or .hangup
			if call.State != f2f.CallIdle {
				matches = append(matches, c.Nickname)
			}
		}
	}

	if len(matches) == 1 {
		return matches[0]
	}
	if len(matches) > 1 {
		// Multiple — fall back to active chat if any of them matches.
		active := node.GetActiveChat()
		if active.String() != "" {
			for _, c := range contacts {
				if c.PeerID == active {
					for _, m := range matches {
						if m == c.Nickname {
							return m
						}
					}
				}
			}
		}
	}

	// No call-based match — for voicecall fall back to active chat partner.
	if !wantIncoming {
		active := node.GetActiveChat()
		if active.String() != "" {
			for _, c := range contacts {
				if c.PeerID == active {
					return c.Nickname
				}
			}
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// .rec — record voice message, auto-send to active chat
// ---------------------------------------------------------------------------

func handleRecord(ui *ConsoleAdapter, node *f2f.Node, rl *readline.Instance, parts []string) {
	active := node.GetActiveChat()
	if active.String() == "" {
		ui.OnLog(f2f.LogLevelWarning, "Голосовое можно записать только в активном чате. Сначала .connect")
		return
	}

	// Optional max-duration argument: .rec 30 → max 30 sec
	maxDur := f2f.DefaultVoiceMaxDuration
	if len(parts) > 1 {
		if n, err := strconv.Atoi(parts[1]); err == nil && n > 0 && n <= 600 {
			maxDur = time.Duration(n) * time.Second
		}
	}

	settings := f2f.LoadSettings()

	rec, err := f2f.NewRecorder(settings.AudioInputDeviceID)
	if err != nil {
		ui.OnLog(f2f.LogLevelError, "Не удалось открыть микрофон: %v", err)
		return
	}
	if err := rec.Start(); err != nil {
		ui.OnLog(f2f.LogLevelError, "Не удалось начать запись: %v", err)
		return
	}

	ui.OnLog(f2f.LogLevelInfo, "[REC] Запись идёт… Нажмите Enter чтобы остановить (макс. %s)", maxDur)

	done := make(chan struct{})
	go func() {
		// Block on Enter via readline
		rl.SetPrompt("")
		_, _ = rl.Readline()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(maxDur):
		ui.OnLog(f2f.LogLevelInfo, "[STOP] Достигнут лимит времени — останавливаю запись")
	}

	rl.SetPrompt("> ")

	pcm, err := rec.Stop()
	if err != nil {
		ui.OnLog(f2f.LogLevelError, "Ошибка остановки записи: %v", err)
		return
	}
	if len(pcm) == 0 {
		ui.OnLog(f2f.LogLevelWarning, "Тишина — ничего не записалось")
		return
	}

	// Name as voicemail-N.wav using per-directory sequential numbering.
	name := f2f.NextVoicemailName(".")
	if err := f2f.WriteWAV(name, f2f.VoiceSampleRate, f2f.VoiceChannels, pcm); err != nil {
		ui.OnLog(f2f.LogLevelError, "Не удалось сохранить WAV: %v", err)
		return
	}

	duration := time.Duration(len(pcm)) * time.Second / time.Duration(f2f.VoiceSampleRate*f2f.VoiceChannels*2)
	ui.OnLog(f2f.LogLevelSuccess, "Записано %s (%d KB) — отправка…", duration.Round(time.Millisecond), len(pcm)/1024)

	if err := node.SendFile(active, name); err != nil {
		ui.OnLog(f2f.LogLevelError, "Отправка: %v", err)
		return
	}
}

// ---------------------------------------------------------------------------
// .play <path> — play a WAV file in-process through the configured output device
// ---------------------------------------------------------------------------

func handlePlay(ui *ConsoleAdapter, parts []string) {
	if len(parts) < 2 {
		ui.OnLog(f2f.LogLevelInfo, "Использование: .play <путь к файлу>")
		return
	}
	path := strings.Join(parts[1:], " ")
	if _, err := os.Stat(path); err != nil {
		ui.OnLog(f2f.LogLevelError, "Файл не найден: %v", err)
		return
	}
	settings := f2f.LoadSettings()
	ui.OnLog(f2f.LogLevelInfo, "> %s", filepath.Base(path))
	if err := f2f.PlayWAV(settings.AudioOutputDeviceID, path); err != nil {
		ui.OnLog(f2f.LogLevelError, "Ошибка воспроизведения: %v", err)
		return
	}
	ui.OnLog(f2f.LogLevelSuccess, "[OK] проиграно")
}

// ---------------------------------------------------------------------------
// .settings — interactive menu for audio devices + voice options
// ---------------------------------------------------------------------------

func handleSettings(ui *ConsoleAdapter, rl *readline.Instance) {
	for {
		settings := f2f.LoadSettings()

		inName := settings.AudioInputDeviceName
		if inName == "" {
			inName = "(по умолчанию)"
		}
		outName := settings.AudioOutputDeviceName
		if outName == "" {
			outName = "(по умолчанию)"
		}
		autoPlay := "выкл"
		if settings.VoiceAutoPlay {
			autoPlay = "вкл"
		}
		videoPath := settings.VideoSourcePath
		if videoPath == "" {
			videoPath = "(не задано)"
		}
		videoType := settings.VideoSourceType
		if videoType == "" {
			videoType = "авто"
		}
		cameraName := settings.VideoCameraID
		if cameraName == "" {
			cameraName = "(первое доступное)"
		}
		ffStatus := "ffmpeg OK"
		if !f2f.CameraAvailable() {
			ffStatus = "ffmpeg НЕ НАЙДЕН — камера не будет работать"
		}

		ui.DrawBox("НАСТРОЙКИ", []string{
			fmt.Sprintf("1) Микрофон:             %s", inName),
			fmt.Sprintf("2) Аудиовыход:           %s", outName),
			fmt.Sprintf("3) Автовоспроизв. голос. %s", autoPlay),
			fmt.Sprintf("4) Тип источника видео:  %s", videoType),
			fmt.Sprintf("5) Камера:               %s", cameraName),
			fmt.Sprintf("6) Файл-заглушка:        %s", videoPath),
			fmt.Sprintf("   (%s)", ffStatus),
			"",
			"0) Выход",
		})

		rl.SetPrompt("settings> ")
		line, err := rl.Readline()
		rl.SetPrompt("> ")
		if err != nil {
			return
		}
		choice := strings.TrimSpace(line)

		switch choice {
		case "0", "":
			return
		case "1":
			pickAudioDevice(ui, rl, true, settings)
		case "2":
			pickAudioDevice(ui, rl, false, settings)
		case "3":
			settings.VoiceAutoPlay = !settings.VoiceAutoPlay
			if err := f2f.SaveSettings(settings); err != nil {
				ui.OnLog(f2f.LogLevelError, "Сохранение: %v", err)
			} else {
				state := "выключено"
				if settings.VoiceAutoPlay {
					state = "включено"
				}
				ui.OnLog(f2f.LogLevelSuccess, "Автовоспроизведение %s", state)
			}
		case "4":
			// Cycle: auto → camera → file → auto
			switch settings.VideoSourceType {
			case "", "auto":
				settings.VideoSourceType = "camera"
			case "camera":
				settings.VideoSourceType = "file"
			default:
				settings.VideoSourceType = ""
			}
			if err := f2f.SaveSettings(settings); err != nil {
				ui.OnLog(f2f.LogLevelError, "Сохранение: %v", err)
			} else {
				ui.OnLog(f2f.LogLevelSuccess, "Тип источника: %s", settings.VideoSourceType)
			}
		case "5":
			pickCameraDevice(ui, rl, settings)
		case "6":
			rl.SetPrompt("путь (png/jpg/gif) или пусто: ")
			raw, err := rl.Readline()
			rl.SetPrompt("> ")
			if err != nil {
				continue
			}
			path := strings.TrimSpace(raw)
			settings.VideoSourcePath = path
			if err := f2f.SaveSettings(settings); err != nil {
				ui.OnLog(f2f.LogLevelError, "Сохранение: %v", err)
			} else if path == "" {
				ui.OnLog(f2f.LogLevelSuccess, "Файл-заглушка сброшен")
			} else {
				ui.OnLog(f2f.LogLevelSuccess, "Файл-заглушка: %s", path)
			}
		default:
			ui.OnLog(f2f.LogLevelWarning, "Неизвестный пункт")
		}
	}
}

func pickCameraDevice(ui *ConsoleAdapter, rl *readline.Instance, settings *f2f.Settings) {
	// Auto-install ffmpeg if missing (Windows only). User sees progress.
	if !ensureFFmpegInstalled(ui) {
		return
	}

	ui.OnLog(f2f.LogLevelInfo, "Опрашиваю ffmpeg — список камер...")
	cams, raw, err := f2f.ListCamerasVerbose()
	if err != nil {
		ui.OnLog(f2f.LogLevelError, "%v", err)
		if raw != "" {
			dumpFFmpegOutput(ui, raw)
		}
		return
	}
	if len(cams) == 0 {
		ui.OnLog(f2f.LogLevelWarning, "Камер не найдено.")
		ui.OnLog(f2f.LogLevelInfo, "Проверь:")
		ui.OnLog(f2f.LogLevelInfo, " — устройство подключено и свободно (OBS/Zoom/Skype не удерживают его)")
		ui.OnLog(f2f.LogLevelInfo, " — Параметры Windows → Конфиденциальность → Камера → доступ РАЗРЕШЁН для десктоп-программ")
		ui.OnLog(f2f.LogLevelInfo, " — камера включена физически (ноутбучные F-клавиши / крышки)")
		if raw != "" {
			ui.OnLog(f2f.LogLevelInfo, "Сырой ответ ffmpeg ниже — при ошибке доступа увидишь почему:")
			dumpFFmpegOutput(ui, raw)
		}
		// Small pause so the user sees the message before the menu redraws.
		waitAnyKey(rl, "Enter чтобы вернуться в меню")
		return
	}

	lines := []string{"0) (первое доступное / не задано)"}
	for i, d := range cams {
		lines = append(lines, fmt.Sprintf("%d) %s", i+1, d))
	}
	ui.DrawBox("КАМЕРЫ", lines)

	rl.SetPrompt("выбор> ")
	line, err := rl.Readline()
	rl.SetPrompt("> ")
	if err != nil {
		return
	}
	n, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || n < 0 || n > len(cams) {
		ui.OnLog(f2f.LogLevelWarning, "Вне диапазона")
		return
	}
	if n == 0 {
		settings.VideoCameraID = ""
	} else {
		settings.VideoCameraID = cams[n-1]
	}
	if err := f2f.SaveSettings(settings); err != nil {
		ui.OnLog(f2f.LogLevelError, "Сохранение: %v", err)
		return
	}
	ui.OnLog(f2f.LogLevelSuccess, "Камера сохранена")
}

func pickAudioDevice(ui *ConsoleAdapter, rl *readline.Instance, input bool, settings *f2f.Settings) {
	devices, err := f2f.ListAudioDevices()
	if err != nil {
		ui.OnLog(f2f.LogLevelError, "Не удалось получить список устройств: %v", err)
		return
	}

	var filtered []f2f.AudioDevice
	for _, d := range devices {
		if d.IsInput == input {
			filtered = append(filtered, d)
		}
	}
	if len(filtered) == 0 {
		ui.OnLog(f2f.LogLevelWarning, "Устройств не найдено")
		return
	}

	title := "МИКРОФОНЫ"
	if !input {
		title = "АУДИОВЫХОДЫ"
	}
	lines := []string{"0) По умолчанию (OS default)"}
	for i, d := range filtered {
		lines = append(lines, fmt.Sprintf("%d) %s", i+1, d.Name))
	}
	ui.DrawBox(title, lines)

	rl.SetPrompt("выбор> ")
	line, err := rl.Readline()
	rl.SetPrompt("> ")
	if err != nil {
		return
	}
	n, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil {
		ui.OnLog(f2f.LogLevelWarning, "Не число")
		return
	}
	if n < 0 || n > len(filtered) {
		ui.OnLog(f2f.LogLevelWarning, "Вне диапазона")
		return
	}

	if input {
		if n == 0 {
			settings.AudioInputDeviceID = ""
			settings.AudioInputDeviceName = ""
		} else {
			settings.AudioInputDeviceID = filtered[n-1].ID
			settings.AudioInputDeviceName = filtered[n-1].Name
		}
	} else {
		if n == 0 {
			settings.AudioOutputDeviceID = ""
			settings.AudioOutputDeviceName = ""
		} else {
			settings.AudioOutputDeviceID = filtered[n-1].ID
			settings.AudioOutputDeviceName = filtered[n-1].Name
		}
	}

	if err := f2f.SaveSettings(settings); err != nil {
		ui.OnLog(f2f.LogLevelError, "Сохранение: %v", err)
		return
	}
	ui.OnLog(f2f.LogLevelSuccess, "Сохранено")
}
