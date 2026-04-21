package tui

import (
	"sort"
	"strings"
)

// commandDef describes one dot-command surface for the IDE-style
// autocomplete popup. The Name is WITHOUT the leading dot.
type commandDef struct {
	Name  string // e.g. "connect"
	Usage string // e.g. "<nick>" — rendered after the name
	Desc  string // short human description
}

// allCommands returns every known dot-command. Pure data — no state.
// Kept alphabetical so autocomplete stays predictable.
func allCommands() []commandDef {
	return []commandDef{
		// Profile / identity
		{"login", "[nick]", "создать / войти в профиль"},
		{"logout", "", "выйти из профиля"},
		{"info", "", "мои данные (peerID, pubkey)"},
		{"fingerprint", "", "fingerprint ключа (160 бит)"},
		{"copy", "", "скопировать .addfriend в буфер обмена"},

		// Contacts
		{"addfriend", "[nick] [peerID] [pubkeyB64]", "добавить контакт"},
		{"removefriend", "[nick]", "удалить контакт"},
		{"list", "", "обновить список контактов"},
		{"check", "", "обновить статусы"},
		{"find", "[nick]", "найти в DHT"},

		// Chat
		{"connect", "[nick]", "начать чат"},
		{"disconnect", "[nick]", "разорвать соединение"},
		{"accept", "[nick]", "принять запрос чата"},
		{"decline", "[nick]", "отклонить запрос чата"},
		{"leave", "", "выйти из активного чата"},

		// Files
		{"file", "[path]", "отправить файл"},
		{"getfile", "", "принять предложенный файл"},
		{"nofile", "", "отклонить / отменить передачу"},

		// Voice messages
		{"rec", "[сек]", "записать голосовое (TODO)"},
		{"play", "[path]", "проиграть WAV"},

		// Calls
		{"call", "[nick]", "голосовой вызов"},
		{"vidcall", "[nick]", "видео-вызов (голос + ASCII)"},
		{"acceptcall", "[nick]", "принять вызов"},
		{"declinecall", "[nick]", "отклонить вызов"},
		{"hangup", "[nick]", "завершить вызов"},
		{"video", "[camera|file|<path>]", "включить видео в вызове"},
		{"stopvideo", "", "остановить видео"},

		// Diagnostics / setup
		{"cameras", "", "список камер"},
		{"ffmpeg", "[install]", "статус / скачать ffmpeg"},
		{"settings", "[autoplay|input|output|camera|file]", "настройки (без аргументов — показать)"},
		{"bootstrap", "", "подключиться к DHT"},

		// Meta
		{"language", "[en|ru|de|fr|zh|ja]", "UI language / язык интерфейса"},
		{"help", "", "список команд"},
		{"quit", "", "выход"},
	}
}

// filterCommands returns the commands that match the given prefix.
// Prefix should NOT include the leading dot.
//
//   - exact matches rank first (input "connect" → [connect])
//   - prefix matches next (input "con" → [connect, contacts?])
//   - fallback substring matches last (input "pic" → [pick?] rare)
//
// Maximum of `limit` results returned.
func filterCommands(cmds []commandDef, prefix string, limit int) []commandDef {
	prefix = strings.ToLower(prefix)
	if prefix == "" {
		out := make([]commandDef, len(cmds))
		copy(out, cmds)
		return out[:min(limit, len(out))]
	}

	var exact, prefixMatch, contains []commandDef
	for _, c := range cmds {
		n := strings.ToLower(c.Name)
		switch {
		case n == prefix:
			exact = append(exact, c)
		case strings.HasPrefix(n, prefix):
			prefixMatch = append(prefixMatch, c)
		case strings.Contains(n, prefix):
			contains = append(contains, c)
		}
	}

	sort.Slice(prefixMatch, func(i, j int) bool { return prefixMatch[i].Name < prefixMatch[j].Name })
	sort.Slice(contains, func(i, j int) bool { return contains[i].Name < contains[j].Name })

	out := append([]commandDef{}, exact...)
	out = append(out, prefixMatch...)
	out = append(out, contains...)
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// filterSubcommands matches subcommand entries by prefix against the FULL
// multi-word Name. So ".settings aut" (prefix="settings aut") matches
// entry "settings autoplay" via HasPrefix. Trailing space in the prefix
// means "I've finished this word" and returns entries that extend it.
func filterSubcommands(subs []commandDef, prefix string, limit int) []commandDef {
	prefix = strings.ToLower(prefix)
	if strings.TrimSpace(prefix) == "" {
		out := make([]commandDef, 0, len(subs))
		for _, s := range subs {
			out = append(out, s)
			if len(out) == limit {
				break
			}
		}
		return out
	}

	var exact, prefixMatch []commandDef
	for _, s := range subs {
		n := strings.ToLower(s.Name)
		switch {
		case n == strings.TrimSpace(prefix):
			exact = append(exact, s)
		case strings.HasPrefix(n, strings.TrimSpace(prefix)):
			prefixMatch = append(prefixMatch, s)
		}
	}
	out := append([]commandDef{}, exact...)
	out = append(out, prefixMatch...)
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// firstWord splits a typed dot-command into command-name and the rest.
// ".connect bob" → "connect", "bob"
// ".connect"     → "connect", ""
// ".con"         → "con", ""
func firstWord(s string) (cmd, rest string) {
	s = strings.TrimPrefix(s, ".")
	idx := strings.IndexByte(s, ' ')
	if idx < 0 {
		return s, ""
	}
	return s[:idx], s[idx+1:]
}
