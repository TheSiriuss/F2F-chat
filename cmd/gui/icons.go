package main

import "runtime"

type IconSet struct {
	Copy      string
	Refresh   string
	Sun       string
	Moon      string
	Chat      string
	Mail      string
	Wave      string
	Check     string
	Cross     string
	Pending   string
	Online    string
	Offline   string
	Connected string
	Arrow     string
	Menu      string
	Logout    string
	Remove    string
}

var Icons IconSet

func init() {
	// Используем ASCII для всех платформ, так как эмодзи требуют специальный шрифт
	Icons = IconSet{
		Copy:      "",
		Refresh:   "",
		Sun:       "",
		Moon:      "",
		Chat:      "",
		Mail:      ">",
		Wave:      "",
		Check:     "+",
		Cross:     "x",
		Pending:   "~",
		Online:    "*",
		Offline:   "-",
		Connected: "#",
		Arrow:     "->",
		Menu:      "...",
		Logout:    "",
		Remove:    "",
	}

	// На Unix можно попробовать простые символы
	if runtime.GOOS != "windows" {
		Icons.Check = "+"
		Icons.Cross = "x"
		Icons.Online = "*"
		Icons.Offline = "o"
	}
}
