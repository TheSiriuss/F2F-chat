package main

import "image/color"

// Theme определяет цветовую схему
type Theme struct {
	Name string

	// Основные
	Background color.NRGBA
	Surface    color.NRGBA
	Sidebar    color.NRGBA
	Text       color.NRGBA
	TextMuted  color.NRGBA
	Divider    color.NRGBA

	// Сообщения
	MsgMine   color.NRGBA
	MsgTheirs color.NRGBA

	// Кнопки контактов
	BtnActive  color.NRGBA
	BtnOffline color.NRGBA
	BtnPending color.NRGBA

	// Акценты
	Primary   color.NRGBA
	Success   color.NRGBA
	Warning   color.NRGBA
	Danger    color.NRGBA
	Secondary color.NRGBA
}

var LightTheme = Theme{
	Name:       "Light",
	Background: color.NRGBA{R: 255, G: 255, B: 255, A: 255},
	Surface:    color.NRGBA{R: 250, G: 250, B: 252, A: 255},
	Sidebar:    color.NRGBA{R: 240, G: 240, B: 245, A: 255},
	Text:       color.NRGBA{R: 30, G: 30, B: 30, A: 255},
	TextMuted:  color.NRGBA{R: 120, G: 120, B: 130, A: 255},
	Divider:    color.NRGBA{R: 200, G: 200, B: 210, A: 255},

	MsgMine:   color.NRGBA{R: 220, G: 240, B: 255, A: 255},
	MsgTheirs: color.NRGBA{R: 240, G: 240, B: 240, A: 255},

	BtnActive:  color.NRGBA{R: 200, G: 230, B: 200, A: 255},
	BtnOffline: color.NRGBA{R: 230, G: 230, B: 230, A: 255},
	BtnPending: color.NRGBA{R: 255, G: 245, B: 200, A: 255},

	Primary:   color.NRGBA{R: 60, G: 130, B: 200, A: 255},
	Success:   color.NRGBA{R: 50, G: 160, B: 50, A: 255},
	Warning:   color.NRGBA{R: 230, G: 150, B: 50, A: 255},
	Danger:    color.NRGBA{R: 200, G: 50, B: 50, A: 255},
	Secondary: color.NRGBA{R: 100, G: 100, B: 110, A: 255},
}

var DarkTheme = Theme{
	Name:       "Dark",
	Background: color.NRGBA{R: 30, G: 30, B: 35, A: 255},
	Surface:    color.NRGBA{R: 40, G: 40, B: 48, A: 255},
	Sidebar:    color.NRGBA{R: 35, G: 35, B: 42, A: 255},
	Text:       color.NRGBA{R: 230, G: 230, B: 235, A: 255},
	TextMuted:  color.NRGBA{R: 140, G: 140, B: 150, A: 255},
	Divider:    color.NRGBA{R: 60, G: 60, B: 70, A: 255},

	MsgMine:   color.NRGBA{R: 45, G: 90, B: 130, A: 255},
	MsgTheirs: color.NRGBA{R: 55, G: 55, B: 65, A: 255},

	BtnActive:  color.NRGBA{R: 40, G: 80, B: 50, A: 255},
	BtnOffline: color.NRGBA{R: 50, G: 50, B: 58, A: 255},
	BtnPending: color.NRGBA{R: 90, G: 75, B: 30, A: 255},

	Primary:   color.NRGBA{R: 80, G: 150, B: 220, A: 255},
	Success:   color.NRGBA{R: 70, G: 180, B: 70, A: 255},
	Warning:   color.NRGBA{R: 240, G: 170, B: 70, A: 255},
	Danger:    color.NRGBA{R: 220, G: 70, B: 70, A: 255},
	Secondary: color.NRGBA{R: 130, G: 130, B: 145, A: 255},
}