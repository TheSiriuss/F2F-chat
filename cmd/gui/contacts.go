package main

import (
	"image"
	"image/color"

	"gioui.org/layout"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"gioui.org/widget/material"

	"github.com/TheSiriuss/F2F-chat/pkg/f2f"
)

// drawContactsList рисует список контактов
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

		// Создаём виджеты для контакта если нет
		if _, ok := s.BtnContacts[c.Nickname]; !ok {
			s.BtnContacts[c.Nickname] = &ContactWidgets{}
		}
		w := s.BtnContacts[c.Nickname]

		// Обработка кликов
		handleContactClicks(gtx, s, c, w, node)

		return layout.Inset{
			Top: unit.Dp(2), Bottom: unit.Dp(2),
			Left: unit.Dp(8), Right: unit.Dp(8),
		}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			switch {
			case c.State == f2f.StatePendingIncoming:
				return drawIncomingRequest(gtx, s, c, w)
			case c.State == f2f.StatePendingOutgoing || c.Connecting:
				return drawPendingContact(gtx, s, c, w)
			default:
				return drawNormalContact(gtx, s, c, w, node)
			}
		})
	})
}

// handleContactClicks обрабатывает клики на контакте
func handleContactClicks(gtx layout.Context, s *UIState, c *f2f.Contact, w *ContactWidgets, node *f2f.Node) {
	if w.ClickMain.Clicked(gtx) {
		if c.State == f2f.StateActive {
			node.EnterChat(c.PeerID)
		} else if c.State == f2f.StateIdle && !c.Connecting {
			go node.InitConnect(c.Nickname)
		}
	}
	if w.ClickAccept.Clicked(gtx) {
		node.HandleDecision(c.Nickname, true)
	}
	if w.ClickDecline.Clicked(gtx) {
		node.HandleDecision(c.Nickname, false)
	}
	if w.ClickDisconnect.Clicked(gtx) {
		go node.Disconnect(c.Nickname)
	}
}

// drawNormalContact рисует обычный контакт
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

	// Обработка меню
	if w.ClickMenu.Clicked(gtx) {
		if isExpanded {
			s.ExpandedContact = ""
		} else {
			s.ExpandedContact = c.Nickname
		}
	}

	// Обработка удаления
	if w.ClickRemove.Clicked(gtx) {
		go node.RemoveFriend(c.Nickname)
		s.ExpandedContact = ""
	}

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		// Основная карточка
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					return w.ClickMain.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return drawContactCard(gtx, s, c.Nickname, status, bgColor)
					})
				}),
				// Кнопка меню
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
		// Выпадающее меню
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if isExpanded && c.State == f2f.StateIdle && !c.Connecting {
				return drawContactMenu(gtx, s, w)
			}
			return layout.Dimensions{}
		}),
	)
}

// drawContactMenu рисует меню контакта
func drawContactMenu(gtx layout.Context, s *UIState, w *ContactWidgets) layout.Dimensions {
	th := s.Theme

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

// drawIncomingRequest рисует входящий запрос
func drawIncomingRequest(gtx layout.Context, s *UIState, c *f2f.Contact, w *ContactWidgets) layout.Dimensions {
	th := s.Theme

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			l := material.Body1(s.MatTheme, "→ "+c.Nickname)
			l.Color = th.Text
			return layout.Inset{Bottom: unit.Dp(4)}.Layout(gtx, l.Layout)
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

// drawPendingContact рисует ожидающий контакт
func drawPendingContact(gtx layout.Context, s *UIState, c *f2f.Contact, w *ContactWidgets) layout.Dimensions {
	th := s.Theme

	status := "Connecting..."
	if c.State == f2f.StatePendingOutgoing {
		status = "Waiting for response..."
	}

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return drawContactCard(gtx, s, c.Nickname, status, th.BtnPending)
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

// drawContactCard рисует карточку контакта
func drawContactCard(gtx layout.Context, s *UIState, nick, status string, bgColor color.NRGBA) layout.Dimensions {
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