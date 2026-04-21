package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/TheSiriuss/aski-chat/pkg/aski"
)

// supportedLanguages lists all language codes with user-readable labels.
// Keep in sync with i18nStrings map keys in i18n.go.
var supportedLanguages = []struct{ Code, Label string }{
	{"en", "English"},
	{"ru", "Русский"},
	{"de", "Deutsch"},
	{"fr", "Français"},
	{"zh", "中文"},
	{"ja", "日本語"},
}

// handleLanguageCmd implements .language:
//
//	.language            — print current + list of codes
//	.language <code>     — switch to the given language and persist it
func handleLanguageCmd(args []string) tea.Cmd {
	if len(args) == 0 {
		return func() tea.Msg {
			var list []string
			for _, l := range supportedLanguages {
				list = append(list, fmt.Sprintf("%s (%s)", l.Code, l.Label))
			}
			return MsgLog{
				Level: f2f.LogLevelInfo,
				Format: fmt.Sprintf(tr("lang.current")+"\n  %s",
					CurrentLanguage(),
					strings.Join(list, "  |  ")),
			}
		}
	}

	code := strings.ToLower(strings.TrimSpace(args[0]))
	found := false
	for _, l := range supportedLanguages {
		if l.Code == code {
			found = true
			break
		}
	}
	if !found {
		return notice(tr("lang.usage"))
	}

	return func() tea.Msg {
		SetLanguage(code)
		s := f2f.LoadSettings()
		s.Language = code
		if err := f2f.SaveSettings(s); err != nil {
			return MsgLog{Level: f2f.LogLevelWarning, Format: "save: " + err.Error()}
		}
		return MsgLog{Level: f2f.LogLevelSuccess, Format: fmt.Sprintf(tr("lang.set"), code)}
	}
}
