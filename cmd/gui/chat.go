package main

import (
	"image"
	"image/color"

	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"gioui.org/widget/material"

	"github.com/TheSiriuss/F2F-chat/pkg/f2f"
)

// drawMainLayout рисует основной лейаут
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

// drawChat рисует область чата
func drawChat(gtx layout.Context, s *UIState, node *f2f.Node) layout.Dimensions {
	th := s.Theme
	paintBackground(gtx, th.Background)

	activeID := node.GetActiveChat()
	if activeID.String() == "" {
		return drawEmptyChat(gtx, s)
	}

	// Находим ник активного контакта
	title := "Chat"
	for _, c := range s.Contacts {
		if c.PeerID == activeID {
			title = c.Nickname
			break
		}
	}

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		// Заголовок
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return drawChatHeader(gtx, s, node, title)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return drawDivider(gtx, th.Divider)
		}),
		// Сообщения
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			return drawMessages(gtx, s)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return drawDivider(gtx, th.Divider)
		}),
		// Панель файлов
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return drawFilePanel(gtx, s, node)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return drawDivider(gtx, th.Divider)
		}),
		// Ввод сообщения
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return drawMessageInput(gtx, s, node)
		}),
	)
}

// drawEmptyChat рисует пустой чат
func drawEmptyChat(gtx layout.Context, s *UIState) layout.Dimensions {
	th := s.Theme

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

// drawChatHeader рисует заголовок чата
func drawChatHeader(gtx layout.Context, s *UIState, node *f2f.Node, title string) layout.Dimensions {
	th := s.Theme

	if s.BtnLeave.Clicked(gtx) {
		go node.LeaveChat()
	}

	paintBackground(gtx, th.Surface)

	return layout.UniformInset(unit.Dp(12)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Spacing: layout.SpaceBetween, Alignment: layout.Middle}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						l := material.H6(s.MatTheme, "Chat: "+title)
						l.Color = th.Text
						return l.Layout(gtx)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						l := material.Caption(s.MatTheme, "Forward Secrecy: ON")
						l.Color = th.Success
						return l.Layout(gtx)
					}),
				)
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

// drawMessages рисует список сообщений
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
		return drawMessage(gtx, s, msg)
	})
}

// drawMessage рисует одно сообщение
func drawMessage(gtx layout.Context, s *UIState, msg UIMessage) layout.Dimensions {
	th := s.Theme

	isMe := msg.Sender == s.MyInfo.Nick
	isSystem := msg.Sender == "System"

	// layout.Direction для Stack: W, Center, E, N, S, NW, NE, SW, SE
	align := layout.W
	bg := th.MsgTheirs

	if isMe {
		align = layout.E
		bg = th.MsgMine
	} else if isSystem || msg.IsFile {
		// Системные сообщения и файлы по центру
		align = layout.Center
		bg = th.Surface
	}

	return layout.Stack{Alignment: align}.Layout(gtx,
		layout.Stacked(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{
				Top: unit.Dp(4), Bottom: unit.Dp(4),
				Left: unit.Dp(12), Right: unit.Dp(12),
			}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				// Ограничиваем ширину
				if !isSystem {
					gtx.Constraints.Max.X = gtx.Constraints.Max.X * 3 / 4
				}

				macro := op.Record(gtx.Ops)
				dims := layout.UniformInset(unit.Dp(10)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
						// Имя отправителя (не для своих и не для системных)
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							if !isMe && !isSystem {
								l := material.Caption(s.MatTheme, msg.Sender)
								l.Color = th.Primary
								return layout.Inset{Bottom: unit.Dp(2)}.Layout(gtx, l.Layout)
							}
							return layout.Dimensions{}
						}),
						// Текст
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							l := material.Body1(s.MatTheme, msg.Text)
							l.Color = th.Text
							return l.Layout(gtx)
						}),
						// Время
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							l := material.Caption(s.MatTheme, msg.Time.Format("15:04"))
							l.Color = th.TextMuted
							return layout.Inset{Top: unit.Dp(2)}.Layout(gtx, l.Layout)
						}),
					)
				})
				c := macro.Stop()

				// Фон сообщения
				rect := image.Rectangle{Max: dims.Size}
				radius := gtx.Dp(12)
				if isSystem {
					radius = gtx.Dp(6)
				}
				paint.FillShape(gtx.Ops, bg, clip.UniformRRect(rect, radius).Op(gtx.Ops))
				c.Add(gtx.Ops)

				return dims
			})
		}),
	)
}

// drawMessageInput рисует поле ввода сообщения
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

	paintBackground(gtx, th.Surface)

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
