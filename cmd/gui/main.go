package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"image"
	"image/color"
	"log"
	"os"
	"strings"

	"sync"
	"time"

	"gioui.org/app"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"

	"github.com/TheSiriuss/F2F-chat/pkg/f2f"
)

// --- Тема ---
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

// UIState хранит состояние
type UIState struct {
	MatTheme *material.Theme
	Theme    *Theme
	Window   *app.Window

	Messages []UIMessage
	Contacts []*f2f.Contact
	MyInfo   MyNodeInfo

	ListChat     widget.List
	ListContacts widget.List

	InputMsg  widget.Editor
	LoginNick widget.Editor

	PasswordInput   widget.Editor
	PasswordConfirm widget.Editor
	BtnUnlock       widget.Clickable
	PasswordError   string
	IsNewUser       bool
	IsUnlocked      bool

	AddNick widget.Editor
	AddID   widget.Editor
	AddKey  widget.Editor

	BtnLogin       widget.Clickable
	BtnSend        widget.Clickable
	BtnAdd         widget.Clickable
	BtnLeave       widget.Clickable
	BtnLogout      widget.Clickable // Кнопка выхода
	BtnCopyID      widget.Clickable // Копировать .addfriend команду
	BtnRefresh     widget.Clickable // .check
	BtnToggleTheme widget.Clickable // Переключить тему

	BtnContacts map[string]*ContactWidgets

	IsLoggedIn bool
	IsDarkMode bool

	// Для уведомления о копировании
	CopyNotification     string
	CopyNotificationTime time.Time

	ExpandedContact string

	mu sync.Mutex
}

type ContactWidgets struct {
	ClickMain       widget.Clickable
	ClickAccept     widget.Clickable
	ClickDecline    widget.Clickable
	ClickDisconnect widget.Clickable
	ClickRemove     widget.Clickable
	ClickMenu       widget.Clickable
}

type MyNodeInfo struct {
	Nick         string
	PeerID       string
	Fingerprint  string
	PeersCount   int
	HasRelay     bool
	AddFriendCmd string // Полная команда .addfriend
}

type UIMessage struct {
	Sender string
	Text   string
	Time   time.Time
}

type GUI struct {
	state *UIState
}

func (g *GUI) OnMessage(_, nick string, text string, t time.Time) {
	g.state.mu.Lock()
	g.state.Messages = append(g.state.Messages, UIMessage{Sender: nick, Text: text, Time: t})
	g.state.ListChat.Position.First = len(g.state.Messages) - 1
	g.state.mu.Unlock()
	g.state.Window.Invalidate()
}

func (g *GUI) OnLog(level, format string, args ...any) {
	msg := fmt.Sprintf("[%s] %s", level, fmt.Sprintf(format, args...))
	log.Println(msg)
}

func (g *GUI) OnContactUpdate() {
	g.state.Window.Invalidate()
}

func (g *GUI) OnChatChanged(_, _ string) {
	g.state.mu.Lock()
	g.state.Messages = nil
	g.state.mu.Unlock()
	g.state.Window.Invalidate()
}

func main() {
	state := &UIState{
		MatTheme:    material.NewTheme(),
		Theme:       &LightTheme,
		BtnContacts: make(map[string]*ContactWidgets),
		IsDarkMode:  false,
		IsNewUser:   f2f.IsNewUser(),
		IsUnlocked:  false,
	}
	state.ListChat.Axis = layout.Vertical
	state.ListContacts.Axis = layout.Vertical
	state.PasswordInput.SingleLine = true
	state.PasswordInput.Mask = '*'
	state.PasswordConfirm.SingleLine = true
	state.PasswordConfirm.Mask = '*'

	gui := &GUI{state: state}

	go func() {
		w := new(app.Window)
		w.Option(app.Title("F2F Messenger"), app.Size(unit.Dp(1000), unit.Dp(700)))
		state.Window = w

		var node *f2f.Node
		ctx := context.Background()

		// ... ticker code ...

		var ops op.Ops

		for {
			switch e := w.Event().(type) {
			case app.DestroyEvent:
				if node != nil {
					node.Shutdown()
				}
				os.Exit(0)

			case app.FrameEvent:
				gtx := app.NewContext(&ops, e)

				// Обработка темы
				if state.BtnToggleTheme.Clicked(gtx) {
					state.IsDarkMode = !state.IsDarkMode
					if state.IsDarkMode {
						state.Theme = &DarkTheme
					} else {
						state.Theme = &LightTheme
					}
				}

				paintColor(gtx, state.Theme.Background)

				// Экран ввода пароля
				if !state.IsUnlocked {
					if state.BtnUnlock.Clicked(gtx) {
						password := state.PasswordInput.Text()

						if state.IsNewUser {
							confirm := state.PasswordConfirm.Text()
							if password != confirm {
								state.PasswordError = "Пароли не совпадают"
							} else if len(password) < 8 {
								state.PasswordError = "Минимум 8 символов"
							} else {
								// Создаём ноду с паролем
								var err error
								node, err = f2f.NewNode(ctx, gui, password)
								if err != nil {
									state.PasswordError = err.Error()
								} else {
									state.IsUnlocked = true
									node.LoadContacts()
								}
							}
						} else {
							// Проверяем пароль
							var err error
							node, err = f2f.NewNode(ctx, gui, password)
							if err != nil {
								if err == f2f.ErrWrongPassword {
									state.PasswordError = "Неверный пароль"
								} else {
									state.PasswordError = err.Error()
								}
							} else {
								state.IsUnlocked = true
								node.LoadContacts()
							}
						}
					}

					drawPasswordScreen(gtx, state)
				} else if !state.IsLoggedIn {
					// ... login screen ...
					if node != nil && node.GetNickname() != "" {
						state.IsLoggedIn = true
					}
					// ... rest of login logic ...
					drawLogin(gtx, state, node)
				} else {
					// ... main layout ...
					state.mu.Lock()
					updateData(state, node)
					state.mu.Unlock()
					drawMainLayout(gtx, state, node)
				}

				e.Frame(gtx.Ops)
			}
		}
	}()

	app.Main()
}

// Новая функция для экрана пароля
func drawPasswordScreen(gtx layout.Context, s *UIState) layout.Dimensions {
	th := s.Theme

	return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical, Alignment: layout.Middle}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				l := material.H3(s.MatTheme, "🔐 F2F Messenger")
				l.Color = th.Text
				return l.Layout(gtx)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(20)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				var msg string
				if s.IsNewUser {
					msg = "Создайте мастер-пароль"
				} else {
					msg = "Введите мастер-пароль"
				}
				l := material.Body1(s.MatTheme, msg)
				l.Color = th.TextMuted
				return l.Layout(gtx)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(20)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return drawStyledEditor(gtx, s, &s.PasswordInput, "Пароль...", 300)
			}),
			// Подтверждение для нового пользователя
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				if s.IsNewUser {
					return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
						layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return drawStyledEditor(gtx, s, &s.PasswordConfirm, "Подтвердите пароль...", 300)
						}),
					)
				}
				return layout.Dimensions{}
			}),
			// Ошибка
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				if s.PasswordError != "" {
					return layout.Inset{Top: unit.Dp(10)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						l := material.Body2(s.MatTheme, s.PasswordError)
						l.Color = th.Danger
						return l.Layout(gtx)
					})
				}
				return layout.Dimensions{}
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(20)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				label := "Войти"
				if s.IsNewUser {
					label = "Создать"
				}
				btn := material.Button(s.MatTheme, &s.BtnUnlock, label)
				btn.Background = th.Primary
				btn.Color = color.NRGBA{R: 255, G: 255, B: 255, A: 255}
				return btn.Layout(gtx)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(30)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return drawThemeToggle(gtx, s)
			}),
		)
	})
}

func updateData(s *UIState, node *f2f.Node) {
	s.Contacts = node.GetContacts()
	peers, relay := node.GetNetworkStatus()

	raw := node.GetIdentityString()
	parts := strings.Fields(raw)
	fp := "Loading..."
	if len(parts) >= 4 {
		bytes, _ := base64.StdEncoding.DecodeString(parts[3])
		fp = f2f.ComputeFingerprint(bytes)
	}

	s.MyInfo = MyNodeInfo{
		Nick:         node.GetNickname(),
		PeerID:       node.GetHostID(),
		Fingerprint:  fp,
		PeersCount:   peers,
		HasRelay:     relay,
		AddFriendCmd: raw,
	}
}

// --- LOGIN ---
func drawLogin(gtx layout.Context, s *UIState, node *f2f.Node) layout.Dimensions {
	if s.BtnLogin.Clicked(gtx) {
		nick := s.LoginNick.Text()
		if nick != "" {
			node.Login(nick)
			s.mu.Lock()
			s.IsLoggedIn = true
			s.mu.Unlock()
		}
	}

	th := s.Theme

	return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical, Alignment: layout.Middle}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				l := material.H3(s.MatTheme, "F2F Messenger")
				l.Color = th.Text
				return l.Layout(gtx)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				l := material.Body2(s.MatTheme, "Secure P2P Chat")
				l.Color = th.TextMuted
				return l.Layout(gtx)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(30)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return drawStyledEditor(gtx, s, &s.LoginNick, "Enter nickname...", 250)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(20)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				btn := material.Button(s.MatTheme, &s.BtnLogin, "LOGIN")
				btn.Background = th.Primary
				btn.Color = color.NRGBA{R: 255, G: 255, B: 255, A: 255}
				return btn.Layout(gtx)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(30)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return drawThemeToggle(gtx, s)
			}),
		)
	})
}

// --- MAIN LAYOUT ---
func drawMainLayout(gtx layout.Context, s *UIState, node *f2f.Node) layout.Dimensions {
	return layout.Flex{}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return drawSidebar(gtx, s, node)
		}),
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			return drawChat(gtx, s, node)
		}),
	)
}

// --- SIDEBAR ---
// --- SIDEBAR ---
func drawSidebar(gtx layout.Context, s *UIState, node *f2f.Node) layout.Dimensions {
	gtx.Constraints.Min.X = gtx.Dp(320)
	gtx.Constraints.Max.X = gtx.Dp(320)

	th := s.Theme
	paintColor(gtx, th.Sidebar)

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return drawMyInfo(gtx, s, node) // <-- ДОБАВЬТЕ node
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return drawDivider(gtx, th.Divider)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return drawToolbar(gtx, s)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return drawDivider(gtx, th.Divider)
		}),
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			return drawContactsList(gtx, s, node)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return drawDivider(gtx, th.Divider)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return drawAddForm(gtx, s, node)
		}),
	)
}

func drawMyInfo(gtx layout.Context, s *UIState, node *f2f.Node) layout.Dimensions {
	th := s.Theme

	// Обработка клика Logout
	if s.BtnLogout.Clicked(gtx) {
		go func() {
			node.Logout()
			s.mu.Lock()
			s.IsLoggedIn = false
			s.Messages = nil
			s.mu.Unlock()
			s.Window.Invalidate()
		}()
	}

	return layout.UniformInset(unit.Dp(12)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			// Ник и кнопки справа
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Alignment: layout.Middle, Spacing: layout.SpaceBetween}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						l := material.H6(s.MatTheme, s.MyInfo.Nick)
						l.Color = th.Text
						return l.Layout(gtx)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
							// Кнопка темы
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return drawThemeToggle(gtx, s)
							}),
							layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
							// Кнопка Logout
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								btn := material.Button(s.MatTheme, &s.BtnLogout, "Logout")
								btn.Background = th.Danger
								btn.Color = color.NRGBA{R: 255, G: 255, B: 255, A: 255}
								btn.TextSize = unit.Sp(12)
								return btn.Layout(gtx)
							}),
						)
					}),
				)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
			// Статус сети
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				stat := "OFFLINE"
				c := th.Danger
				if s.MyInfo.PeersCount > 0 {
					stat = fmt.Sprintf("ONLINE (%d peers)", s.MyInfo.PeersCount)
					c = th.Success
				}
				if s.MyInfo.HasRelay {
					stat = "GLOBAL (Relay)"
					c = th.Primary
				}
				l := material.Body2(s.MatTheme, stat)
				l.Color = c
				return l.Layout(gtx)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
			// Fingerprint
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				l := material.Caption(s.MatTheme, "FP: "+s.MyInfo.Fingerprint)
				l.Color = th.TextMuted
				return l.Layout(gtx)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
			// Кнопка копирования
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
					layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
						btn := material.Button(s.MatTheme, &s.BtnCopyID, "Copy AddFriend")
						btn.Background = th.Secondary
						btn.Color = color.NRGBA{R: 255, G: 255, B: 255, A: 255}
						btn.TextSize = unit.Sp(12)
						return btn.Layout(gtx)
					}),
				)
			}),
			// Уведомление о копировании
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				if s.CopyNotification != "" {
					l := material.Caption(s.MatTheme, s.CopyNotification)
					l.Color = th.Success
					return layout.Inset{Top: unit.Dp(4)}.Layout(gtx, l.Layout)
				}
				return layout.Dimensions{}
			}),
		)
	})
}

func drawNormalContact(gtx layout.Context, s *UIState, c *f2f.Contact, w *ContactWidgets, node *f2f.Node) layout.Dimensions {
	th := s.Theme
	status := c.Presence.String()
	bgColor := th.BtnOffline

	if c.State == f2f.StateActive {
		status = "IN CHAT"
		bgColor = th.BtnActive
	} else if c.Presence == f2f.PresenceOnline {
		status = "ONLINE (tap to connect)"
		bgColor = th.BtnActive
	} else if c.Presence == f2f.PresenceChecking {
		status = "Checking..."
	}

	isExpanded := s.ExpandedContact == c.Nickname

	// Обработка клика на меню "..."
	if w.ClickMenu.Clicked(gtx) {
		if isExpanded {
			s.ExpandedContact = ""
		} else {
			s.ExpandedContact = c.Nickname
		}
	}

	// Обработка удаления контакта
	if w.ClickRemove.Clicked(gtx) {
		go node.RemoveFriend(c.Nickname)
		s.ExpandedContact = ""
	}

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		// Основная карточка контакта
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
				// Кликабельная часть контакта
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					return w.ClickMain.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return drawContactCardColored(gtx, s, c.Nickname, status, bgColor)
					})
				}),
				// Кнопка меню "..."
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					if c.State == f2f.StateIdle && !c.Connecting {
						return layout.Inset{Left: unit.Dp(4)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
							menuBg := th.Surface
							if isExpanded {
								menuBg = th.Primary
							}
							btn := material.Button(s.MatTheme, &w.ClickMenu, "...")
							btn.Background = menuBg
							btn.Color = th.Text
							btn.TextSize = unit.Sp(14)
							gtx.Constraints.Max.X = gtx.Dp(36)
							gtx.Constraints.Min.X = gtx.Dp(36)
							return btn.Layout(gtx)
						})
					}
					return layout.Dimensions{}
				}),
			)
		}),
		// Выпадающее меню с опциями
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if isExpanded && c.State == f2f.StateIdle && !c.Connecting {
				return layout.Inset{Top: unit.Dp(4), Bottom: unit.Dp(4)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					return layout.Stack{}.Layout(gtx,
						layout.Expanded(func(gtx layout.Context) layout.Dimensions {
							r := gtx.Dp(6)
							rect := image.Rectangle{Max: gtx.Constraints.Min}
							paint.FillShape(gtx.Ops, th.Surface, clip.UniformRRect(rect, r).Op(gtx.Ops))
							return layout.Dimensions{Size: gtx.Constraints.Min}
						}),
						layout.Stacked(func(gtx layout.Context) layout.Dimensions {
							return layout.UniformInset(unit.Dp(8)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
								btn := material.Button(s.MatTheme, &w.ClickRemove, "Remove Contact")
								btn.Background = th.Danger
								btn.Color = color.NRGBA{R: 255, G: 255, B: 255, A: 255}
								btn.TextSize = unit.Sp(12)
								return btn.Layout(gtx)
							})
						}),
					)
				})
			}
			return layout.Dimensions{}
		}),
	)
}

func drawToolbar(gtx layout.Context, s *UIState) layout.Dimensions {
	th := s.Theme

	return layout.UniformInset(unit.Dp(8)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Alignment: layout.Middle, Spacing: layout.SpaceEvenly}.Layout(gtx,
			layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
				btn := material.Button(s.MatTheme, &s.BtnRefresh, "Refresh Status")
				btn.Background = th.Primary
				btn.Color = color.NRGBA{R: 255, G: 255, B: 255, A: 255}
				btn.TextSize = unit.Sp(12)
				return btn.Layout(gtx)
			}),
		)
	})
}

func drawThemeToggle(gtx layout.Context, s *UIState) layout.Dimensions {
	th := s.Theme
	label := "Light"
	if s.IsDarkMode {
		label = "Dark"
	}

	btn := material.Button(s.MatTheme, &s.BtnToggleTheme, label)
	btn.Background = th.Surface
	btn.Color = th.Text
	btn.TextSize = unit.Sp(11)
	return btn.Layout(gtx)
}

func drawContactsList(gtx layout.Context, s *UIState, node *f2f.Node) layout.Dimensions {
	th := s.Theme

	if len(s.Contacts) == 0 {
		return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			l := material.Body2(s.MatTheme, "No contacts yet")
			l.Color = th.TextMuted
			return l.Layout(gtx)
		})
	}

	return material.List(s.MatTheme, &s.ListContacts).Layout(gtx, len(s.Contacts), func(gtx layout.Context, i int) layout.Dimensions {
		c := s.Contacts[i]
		if _, ok := s.BtnContacts[c.Nickname]; !ok {
			s.BtnContacts[c.Nickname] = &ContactWidgets{}
		}
		widgets := s.BtnContacts[c.Nickname]

		// Обработка кликов
		if widgets.ClickMain.Clicked(gtx) {
			if c.State == f2f.StateActive {
				node.EnterChat(c.PeerID)
			} else if c.State == f2f.StateIdle && !c.Connecting {
				go node.InitConnect(c.Nickname)
			}
		}
		if widgets.ClickAccept.Clicked(gtx) {
			node.HandleDecision(c.Nickname, true)
		}
		if widgets.ClickDecline.Clicked(gtx) {
			node.HandleDecision(c.Nickname, false)
		}
		if widgets.ClickDisconnect.Clicked(gtx) {
			go node.Disconnect(c.Nickname)
		}

		return layout.Inset{Top: unit.Dp(2), Bottom: unit.Dp(2), Left: unit.Dp(8), Right: unit.Dp(8)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {

			// ВХОДЯЩИЙ запрос
			if c.State == f2f.StatePendingIncoming {
				return drawIncomingRequest(gtx, s, c, widgets)
			}

			// ИСХОДЯЩИЙ запрос или CONNECTING
			if c.State == f2f.StatePendingOutgoing || c.Connecting {
				return drawPendingContact(gtx, s, c, widgets)
			}

			// Обычное состояние
			return drawNormalContact(gtx, s, c, widgets, node)
		})
	})
}

func drawIncomingRequest(gtx layout.Context, s *UIState, c *f2f.Contact, w *ContactWidgets) layout.Dimensions {
	th := s.Theme

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Bottom: unit.Dp(4)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				l := material.Body1(s.MatTheme, "> "+c.Nickname)
				l.Color = th.Text
				return l.Layout(gtx)
			})
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			l := material.Caption(s.MatTheme, "Incoming request")
			l.Color = th.Warning
			return l.Layout(gtx)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{}.Layout(gtx,
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					btn := material.Button(s.MatTheme, &w.ClickAccept, "Accept")
					btn.Background = th.Success
					btn.Color = color.NRGBA{R: 255, G: 255, B: 255, A: 255}
					btn.TextSize = unit.Sp(12)
					return btn.Layout(gtx)
				}),
				layout.Rigid(layout.Spacer{Width: unit.Dp(6)}.Layout),
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					btn := material.Button(s.MatTheme, &w.ClickDecline, "Decline")
					btn.Background = th.Danger
					btn.Color = color.NRGBA{R: 255, G: 255, B: 255, A: 255}
					btn.TextSize = unit.Sp(12)
					return btn.Layout(gtx)
				}),
			)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
	)
}

func drawPendingContact(gtx layout.Context, s *UIState, c *f2f.Contact, w *ContactWidgets) layout.Dimensions {
	th := s.Theme
	status := "Connecting..."
	if c.State == f2f.StatePendingOutgoing {
		status = "Waiting for response..."
	}

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return drawContactCardColored(gtx, s, c.Nickname, status, th.BtnPending)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			btn := material.Button(s.MatTheme, &w.ClickDisconnect, "✕ Cancel")
			btn.Background = th.Warning
			btn.Color = color.NRGBA{R: 255, G: 255, B: 255, A: 255}
			btn.TextSize = unit.Sp(12)
			return btn.Layout(gtx)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
	)
}

func drawContactCardColored(gtx layout.Context, s *UIState, nick, status string, bgColor color.NRGBA) layout.Dimensions {
	th := s.Theme

	return layout.Stack{}.Layout(gtx,
		layout.Expanded(func(gtx layout.Context) layout.Dimensions {
			r := gtx.Dp(8)
			rect := image.Rectangle{Max: gtx.Constraints.Min}
			paint.FillShape(gtx.Ops, bgColor, clip.UniformRRect(rect, r).Op(gtx.Ops))
			return layout.Dimensions{Size: gtx.Constraints.Min}
		}),
		layout.Stacked(func(gtx layout.Context) layout.Dimensions {
			return layout.UniformInset(unit.Dp(10)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						l := material.Body1(s.MatTheme, nick)
						l.Color = th.Text
						return l.Layout(gtx)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						l := material.Caption(s.MatTheme, status)
						l.Color = th.TextMuted
						return l.Layout(gtx)
					}),
				)
			})
		}),
	)
}

func drawAddForm(gtx layout.Context, s *UIState, node *f2f.Node) layout.Dimensions {
	th := s.Theme

	if s.BtnAdd.Clicked(gtx) {
		nick := s.AddNick.Text()
		id := s.AddID.Text()
		key := s.AddKey.Text()
		if nick != "" && id != "" && key != "" {
			go node.AddFriend(nick, id, key)
			s.AddNick.SetText("")
			s.AddID.SetText("")
			s.AddKey.SetText("")
		}
	}

	return layout.UniformInset(unit.Dp(10)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				l := material.Body2(s.MatTheme, "Add Friend:")
				l.Color = th.Text
				return l.Layout(gtx)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return drawStyledEditor(gtx, s, &s.AddNick, "Nickname", 0)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return drawStyledEditor(gtx, s, &s.AddID, "PeerID", 0)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(4)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return drawStyledEditor(gtx, s, &s.AddKey, "PubKey", 0)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				btn := material.Button(s.MatTheme, &s.BtnAdd, "Add Contact")
				btn.Background = th.Primary
				btn.Color = color.NRGBA{R: 255, G: 255, B: 255, A: 255}
				return btn.Layout(gtx)
			}),
		)
	})
}

func drawStyledEditor(gtx layout.Context, s *UIState, editor *widget.Editor, hint string, minWidth int) layout.Dimensions {
	th := s.Theme

	// Фон для редактора
	return layout.Stack{}.Layout(gtx,
		layout.Expanded(func(gtx layout.Context) layout.Dimensions {
			r := gtx.Dp(4)
			rect := image.Rectangle{Max: gtx.Constraints.Min}
			paint.FillShape(gtx.Ops, th.Surface, clip.UniformRRect(rect, r).Op(gtx.Ops))
			return layout.Dimensions{Size: gtx.Constraints.Min}
		}),
		layout.Stacked(func(gtx layout.Context) layout.Dimensions {
			if minWidth > 0 {
				gtx.Constraints.Min.X = gtx.Dp(unit.Dp(minWidth))
			}
			return layout.UniformInset(unit.Dp(8)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				e := material.Editor(s.MatTheme, editor, hint)
				e.Color = th.Text
				e.HintColor = th.TextMuted
				return e.Layout(gtx)
			})
		}),
	)
}

// --- CHAT ---
func drawChat(gtx layout.Context, s *UIState, node *f2f.Node) layout.Dimensions {
	th := s.Theme
	paintColor(gtx, th.Background)

	activeID := node.GetActiveChat()
	if activeID.String() == "" {
		return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical, Alignment: layout.Middle}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					l := material.H5(s.MatTheme, "Select a contact")
					l.Color = th.TextMuted
					return l.Layout(gtx)
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					l := material.Body2(s.MatTheme, "Click on an online contact to start chatting")
					l.Color = th.TextMuted
					return l.Layout(gtx)
				}),
			)
		})
	}

	title := "Chat"
	for _, c := range s.Contacts {
		if c.PeerID == activeID {
			title = c.Nickname
			break
		}
	}

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return drawChatHeader(gtx, s, node, title)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return drawDivider(gtx, th.Divider)
		}),
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			return drawMessages(gtx, s)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return drawDivider(gtx, th.Divider)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return drawMessageInput(gtx, s, node)
		}),
	)
}

func drawChatHeader(gtx layout.Context, s *UIState, node *f2f.Node, title string) layout.Dimensions {
	th := s.Theme

	if s.BtnLeave.Clicked(gtx) {
		go node.LeaveChat()
	}

	paintColor(gtx, th.Surface)

	return layout.UniformInset(unit.Dp(12)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Spacing: layout.SpaceBetween, Alignment: layout.Middle}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				l := material.H6(s.MatTheme, "Chat: "+title)
				l.Color = th.Text
				return l.Layout(gtx)
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				btn := material.Button(s.MatTheme, &s.BtnLeave, "Disconnect")
				btn.Background = th.Danger
				btn.Color = color.NRGBA{R: 255, G: 255, B: 255, A: 255}
				return btn.Layout(gtx)
			}),
		)
	})
}

func drawMessages(gtx layout.Context, s *UIState) layout.Dimensions {
	th := s.Theme

	if len(s.Messages) == 0 {
		return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			l := material.Body2(s.MatTheme, "No messages yet. Say hi!")
			l.Color = th.TextMuted
			return l.Layout(gtx)
		})
	}

	return material.List(s.MatTheme, &s.ListChat).Layout(gtx, len(s.Messages), func(gtx layout.Context, i int) layout.Dimensions {
		msg := s.Messages[i]
		isMe := msg.Sender == s.MyInfo.Nick
		align := layout.W
		bg := th.MsgTheirs
		if isMe {
			align = layout.E
			bg = th.MsgMine
		}

		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Stack{Alignment: align}.Layout(gtx,
					layout.Stacked(func(gtx layout.Context) layout.Dimensions {
						return layout.Inset{Top: unit.Dp(4), Bottom: unit.Dp(4), Left: unit.Dp(12), Right: unit.Dp(12)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
							// Ограничиваем ширину сообщения
							gtx.Constraints.Max.X = gtx.Constraints.Max.X * 3 / 4

							macro := op.Record(gtx.Ops)
							dims := layout.UniformInset(unit.Dp(10)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
								return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										if !isMe {
											l := material.Caption(s.MatTheme, msg.Sender)
											l.Color = th.Primary
											return layout.Inset{Bottom: unit.Dp(2)}.Layout(gtx, l.Layout)
										}
										return layout.Dimensions{}
									}),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										l := material.Body1(s.MatTheme, msg.Text)
										l.Color = th.Text
										return l.Layout(gtx)
									}),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										l := material.Caption(s.MatTheme, msg.Time.Format("15:04"))
										l.Color = th.TextMuted
										return layout.Inset{Top: unit.Dp(2)}.Layout(gtx, l.Layout)
									}),
								)
							})
							c := macro.Stop()
							rect := image.Rectangle{Max: dims.Size}
							paint.FillShape(gtx.Ops, bg, clip.UniformRRect(rect, gtx.Dp(12)).Op(gtx.Ops))
							c.Add(gtx.Ops)
							return dims
						})
					}),
				)
			}),
		)
	})
}

func drawMessageInput(gtx layout.Context, s *UIState, node *f2f.Node) layout.Dimensions {
	th := s.Theme

	if s.BtnSend.Clicked(gtx) {
		txt := s.InputMsg.Text()
		id := node.GetActiveChat()
		if txt != "" && id.String() != "" {
			node.SendChatMessage(id, txt)
			s.InputMsg.SetText("")
		}
	}

	paintColor(gtx, th.Surface)

	return layout.UniformInset(unit.Dp(10)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
			layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
				return drawStyledEditor(gtx, s, &s.InputMsg, "Type a message...", 0)
			}),
			layout.Rigid(layout.Spacer{Width: unit.Dp(10)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				btn := material.Button(s.MatTheme, &s.BtnSend, "Send")
				btn.Background = th.Primary
				btn.Color = color.NRGBA{R: 255, G: 255, B: 255, A: 255}
				return btn.Layout(gtx)
			}),
		)
	})
}

// --- UTILS ---
func paintColor(gtx layout.Context, c color.NRGBA) {
	rect := clip.Rect{Max: gtx.Constraints.Max}
	paint.FillShape(gtx.Ops, c, rect.Op())
}

func drawDivider(gtx layout.Context, c color.NRGBA) layout.Dimensions {
	paint.FillShape(gtx.Ops, c, clip.Rect{Max: image.Pt(gtx.Constraints.Max.X, 1)}.Op())
	return layout.Dimensions{Size: image.Pt(gtx.Constraints.Max.X, 1)}
}
