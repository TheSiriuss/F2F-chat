package tui

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/TheSiriuss/aski-chat/pkg/aski"
)

// -----------------------------------------------------------------------------
// Panel renderers — produce multi-line, lipgloss-boxed strings that commands
// like .info / .list inject into chat history. Same visual vocabulary as the
// old DrawBox output, but now inline in the scrollable chat pane.
// -----------------------------------------------------------------------------

// boxed wraps content in a rounded accent-coloured border with a title.
// `width` is the TOTAL outer width the box must occupy (including borders
// and padding) — we subtract off the 4 non-content columns internally so
// the final rendered box fits exactly inside the viewport's Width, and
// its right border isn't truncated.
//
// NOTE on lipgloss behaviour: Style.Width() constrains the CONTENT area,
// not the outer box. Border (1) + Padding (1) on each side = 4 extra
// columns that lipgloss adds on top. We compensate here.
func boxed(sty styles, title, content string, width int) string {
	inner := sty.overlayTitle.Render(title) + "\n" + content
	st := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(colAccent).
		Padding(0, 1)
	if width > 4 {
		st = st.Width(width - 4)
	}
	return st.Render(inner)
}

// renderInfoBox recreates the old "ВАШИ ДАННЫЕ" panel — nick, status,
// PeerID, fingerprint, and the .addfriend command to hand to a friend.
func renderInfoBox(node *f2f.Node, sty styles, width int) string {
	if node == nil {
		return sty.msgSystem.Render("(node not initialised)")
	}
	raw := node.GetIdentityString()
	if !strings.HasPrefix(raw, ".addfriend ") {
		return boxed(sty, tr("info.title"),
			sty.msgWarn.Render(tr("info.notlogged")), width)
	}
	parts := strings.Fields(raw)
	if len(parts) < 4 {
		return boxed(sty, tr("info.title"),
			sty.msgErr.Render("bad identity string"), width)
	}

	nick := parts[1]
	peerID := parts[2]
	pubkey := parts[3]

	fp := "(N/A)"
	if raw, err := base64.StdEncoding.DecodeString(pubkey); err == nil {
		fp = f2f.ComputeFingerprint(raw)
	}

	peers, hasRelay := node.GetNetworkStatus()
	status := fmt.Sprintf("ONLINE • %d peers", peers)
	if hasRelay {
		status = sty.msgOK.Render(status) + " " + sty.msgSystem.Render("via relay")
	} else {
		status = sty.msgOK.Render(status)
	}

	rows := []string{
		sty.msgTS.Render(pad(tr("info.nick"), 9)) + sty.msgPeer.Render(nick),
		sty.msgTS.Render(pad(tr("info.status"), 9)) + status,
		sty.msgTS.Render(pad(tr("info.peerid"), 9)) + peerID,
		sty.msgTS.Render(pad(tr("info.fp"), 9)) + sty.msgOwn.Render(fp),
		"",
		sty.msgSystem.Render(tr("info.copyhint")),
	}
	return boxed(sty, tr("info.title"), strings.Join(rows, "\n"), width)
}

// renderFingerprintBox is a shorter info box focused on just the fingerprint.
func renderFingerprintBox(node *f2f.Node, sty styles, width int) string {
	raw := node.GetIdentityString()
	parts := strings.Fields(raw)
	if len(parts) < 4 {
		return sty.msgWarn.Render(tr("fp.notlogged"))
	}
	bin, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		return sty.msgErr.Render("bad pubkey: " + err.Error())
	}
	fp := f2f.ComputeFingerprint(bin)
	content := sty.msgTS.Render(tr("info.fp")+" ") + sty.msgOwn.Render(fp) + "\n" +
		sty.msgSystem.Render(tr("fp.hint"))
	return boxed(sty, tr("fp.title"), content, width)
}

// renderContactsBox lists all contacts with status icons — same layout as
// the sidebar but as a full-width panel in the chat pane.
func renderContactsBox(contacts []*f2f.Contact, sty styles, width int) string {
	if len(contacts) == 0 {
		return boxed(sty, tr("contacts.title"),
			sty.msgSystem.Render(tr("contacts.empty")), width)
	}
	var rows []string
	for _, c := range contacts {
		icon, label := contactIcon(c)
		nick := sty.msgPeer.Render(pad(c.Nickname, 14))
		stat := sty.msgTS.Render(label)
		rows = append(rows, fmt.Sprintf("%s %s %s", icon, nick, stat))
	}
	return boxed(sty, tr("contacts.title"), strings.Join(rows, "\n"), width)
}

// renderSettingsPanel dumps the current persisted settings in a readable
// form, plus hints on how to change them. We don't ship a full in-TUI
// settings editor — users tweak via dedicated sub-commands or settings.json.
func renderSettingsPanel(sty styles, width int) string {
	s := f2f.LoadSettings()
	or := func(v, placeholder string) string {
		if v == "" {
			return sty.msgSystem.Render(placeholder)
		}
		return v
	}

	autoPlay := "off"
	if s.VoiceAutoPlay {
		autoPlay = "on"
	}

	ffmpeg := "not found"
	if f2f.CameraAvailable() {
		ffmpeg = f2f.ResolveFFmpeg()
	}

	rows := []string{
		sty.msgTS.Render(pad(tr("settings.input"), 17)) + or(s.AudioInputDeviceName, "(default)"),
		sty.msgTS.Render(pad(tr("settings.output"), 17)) + or(s.AudioOutputDeviceName, "(default)"),
		sty.msgTS.Render(pad(tr("settings.autoplay"), 17)) + autoPlay,
		sty.msgTS.Render(pad(tr("settings.vsource"), 17)) + or(s.VideoSourceType, "auto"),
		sty.msgTS.Render(pad(tr("settings.camid"), 17)) + or(s.VideoCameraID, "(first)"),
		sty.msgTS.Render(pad(tr("settings.vfile"), 17)) + or(s.VideoSourcePath, "(not set)"),
		sty.msgTS.Render(pad(tr("settings.ffmpeg"), 17)) + ffmpeg,
		"",
		sty.msgSystem.Render(tr("settings.cmdhint")),
		"  .settings autoplay            " + sty.msgSystem.Render(tr("settings.cmd.autoplay")),
		"  .settings input               " + sty.msgSystem.Render(tr("settings.cmd.input")),
		"  .settings output              " + sty.msgSystem.Render(tr("settings.cmd.output")),
		"  .settings camera              " + sty.msgSystem.Render(tr("settings.cmd.camera")),
		"  .settings file [path|clear]   " + sty.msgSystem.Render(tr("settings.cmd.file")),
		"  .ffmpeg install               " + sty.msgSystem.Render(tr("settings.cmd.ffmpeg")),
	}
	return boxed(sty, tr("settings.title"), strings.Join(rows, "\n"), width)
}

// renderCamerasPanel surfaces the live ffmpeg camera enumeration result
// as a panel in the chat pane. Index 0 is ALWAYS the built-in ASCII
// avatar (zero setup, no ffmpeg) — the fallback for users without a
// camera or who don't want to share one. 1..N are real webcams.
func renderCamerasPanel(sty styles, width int) string {
	s := f2f.LoadSettings()
	asciiSelected := s.VideoSourceType == "ascii"
	cameraSelected := s.VideoSourceType == "camera"

	asciiLine := "  " + tr("panel.cameras.ascii_row")
	if asciiSelected {
		asciiLine = sty.msgOwn.Render("  " + tr("panel.cameras.ascii_row") + "  " + tr("panel.cameras.selected"))
	}

	var rows []string

	if !f2f.CameraAvailable() {
		rows = append(rows,
			asciiLine,
			"",
			sty.msgWarn.Render(tr("panel.cameras.ffmpeg_missing")),
			sty.msgSystem.Render(tr("panel.cameras.install_hint")),
			"",
			sty.msgSystem.Render(tr("panel.cameras.pick")),
		)
		return boxed(sty, tr("panel.cameras.title"), strings.Join(rows, "\n"), width)
	}

	cams, raw, err := f2f.ListCamerasVerbose()
	if err != nil {
		rows = append(rows,
			asciiLine,
			"",
			sty.msgErr.Render("ffmpeg: "+err.Error()),
			"",
			sty.msgSystem.Render(tr("panel.cameras.pick")),
		)
		return boxed(sty, tr("panel.cameras.title"), strings.Join(rows, "\n"), width)
	}

	if len(cams) == 0 {
		rows = append(rows,
			asciiLine,
			"",
			sty.msgWarn.Render(tr("panel.cameras.none")),
			sty.msgSystem.Render(tr("panel.cameras.check")),
			"",
			sty.msgSystem.Render(tr("panel.cameras.pick")),
		)
	} else {
		rows = append(rows, sty.msgOK.Render(fmt.Sprintf(tr("panel.cameras.found"), len(cams))))
		rows = append(rows, asciiLine)
		for i, c := range cams {
			line := fmt.Sprintf("  %d) %s", i+1, c)
			if cameraSelected && c == s.VideoCameraID {
				line = sty.msgOwn.Render(line + "  " + tr("panel.cameras.selected"))
			}
			rows = append(rows, line)
		}
		rows = append(rows, "", sty.msgSystem.Render(tr("panel.cameras.pick")))
	}
	if raw != "" {
		rows = append(rows, "", sty.msgTS.Render("raw ffmpeg output:"))
		for _, l := range strings.Split(raw, "\n") {
			l = strings.TrimRight(l, "\r\n ")
			if l == "" {
				continue
			}
			rows = append(rows, "  "+sty.msgSystem.Render(l))
		}
	}
	return boxed(sty, "CAMERAS", strings.Join(rows, "\n"), width)
}

// renderAudioDevicesPanel lists the available audio devices (input OR output)
// numbered so users can pick one via `.settings input <N>` / `.settings output <N>`.
// Shows current selection in bold, "0) (default)" at the top as fallback.
func renderAudioDevicesPanel(sty styles, width int, wantInput bool) string {
	title := tr("panel.audio.input_title")
	pickHint := tr("panel.audio.pick_input")
	if !wantInput {
		title = tr("panel.audio.output_title")
		pickHint = tr("panel.audio.pick_output")
	}

	devices, err := f2f.ListAudioDevices()
	if err != nil {
		return boxed(sty, title, sty.msgErr.Render(err.Error()), width)
	}
	var filtered []f2f.AudioDevice
	for _, d := range devices {
		if d.IsInput == wantInput {
			filtered = append(filtered, d)
		}
	}

	s := f2f.LoadSettings()
	currentID := s.AudioInputDeviceID
	if !wantInput {
		currentID = s.AudioOutputDeviceID
	}

	var rows []string
	prefix0 := "0) (default)"
	if currentID == "" {
		prefix0 = sty.msgOwn.Render(prefix0 + "  " + tr("panel.cameras.selected"))
	}
	rows = append(rows, prefix0)
	if len(filtered) == 0 {
		rows = append(rows, sty.msgWarn.Render(tr("panel.audio.none")))
	}
	for i, d := range filtered {
		line := fmt.Sprintf("%d) %s", i+1, d.Name)
		if d.ID == currentID && currentID != "" {
			line = sty.msgOwn.Render(line + "  " + tr("panel.cameras.selected"))
		}
		rows = append(rows, line)
	}
	rows = append(rows, "", sty.msgSystem.Render(pickHint))
	return boxed(sty, title, strings.Join(rows, "\n"), width)
}

// renderCallBanner renders a prominent lipgloss-boxed notification for a
// call lifecycle event. Always goes into the peer's history lane so the
// user sees it regardless of their active chat at event-fire time.
func renderCallBanner(sty styles, width int, title, subtitle, hint string) string {
	lines := []string{
		sty.msgOwn.Render(subtitle),
		"",
		sty.msgSystem.Render(hint),
	}
	return boxed(sty, title, strings.Join(lines, "\n"), width)
}

// renderWelcomePanel is the banner shown on first startup. Shows the big
// "ASKI CHAT" ASCII banner centered, followed by a short quickstart.
func renderWelcomePanel(sty styles, width int) string {
	inner := width - 4 // box borders + padding
	if inner < 20 {
		inner = 20
	}

	// Centre each line of the embedded banner using lipgloss.
	bannerLines := strings.Split(strings.TrimRight(askiBanner, "\n"), "\n")
	var centered []string
	for _, line := range bannerLines {
		centered = append(centered, lipgloss.NewStyle().
			Foreground(colAccent).
			Width(inner).
			Align(lipgloss.Center).
			Render(line))
	}
	banner := strings.Join(centered, "\n")

	subtitle := lipgloss.NewStyle().Width(inner).Align(lipgloss.Center).
		Render(sty.msgOwn.Render(tr("welcome.tagline")))
	sec := lipgloss.NewStyle().Width(inner).Align(lipgloss.Center).
		Render(sty.msgSystem.Render(tr("welcome.sec")))
	features := lipgloss.NewStyle().Width(inner).Align(lipgloss.Center).
		Render(sty.msgSystem.Render(tr("welcome.features")))

	lines := []string{
		banner,
		"",
		subtitle,
		sec,
		features,
		"",
		sty.msgTS.Render(tr("welcome.start")),
		"  " + sty.helpKey.Render(".bootstrap") + sty.helpText.Render("      "+tr("welcome.bootstrap")),
		"  " + sty.helpKey.Render(".addfriend [...]") + sty.helpText.Render(" "+tr("welcome.addfriend")),
		"  " + sty.helpKey.Render(".connect [nick]") + sty.helpText.Render("  "+tr("welcome.connect")),
		"",
		sty.msgSystem.Render(tr("welcome.dothint")),
	}
	return boxed(sty, tr("welcome.title"), strings.Join(lines, "\n"), width)
}
