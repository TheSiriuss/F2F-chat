package main

import (
	"encoding/base64"
	"strings"
	"sync"
	"time"

	"gioui.org/app"
	"gioui.org/layout"
	"gioui.org/widget"
	"gioui.org/widget/material"

	"github.com/TheSiriuss/F2F-chat/pkg/f2f"
)

// UIState хранит всё состояние интерфейса
type UIState struct {
	MatTheme *material.Theme
	Theme    *Theme
	Window   *app.Window

	// Данные
	Messages []UIMessage
	Contacts []*f2f.Contact
	MyInfo   MyNodeInfo

	// Списки
	ListChat     widget.List
	ListContacts widget.List

	// Редакторы
	InputMsg        widget.Editor
	LoginNick       widget.Editor
	PasswordInput   widget.Editor
	PasswordConfirm widget.Editor
	AddNick         widget.Editor
	AddID           widget.Editor
	AddKey          widget.Editor

	// Кнопки
	BtnLogin       widget.Clickable
	BtnSend        widget.Clickable
	BtnAdd         widget.Clickable
	BtnLeave       widget.Clickable
	BtnLogout      widget.Clickable
	BtnCopyID      widget.Clickable
	BtnRefresh     widget.Clickable
	BtnToggleTheme widget.Clickable
	BtnUnlock      widget.Clickable

	// Виджеты контактов
	BtnContacts map[string]*ContactWidgets

	// Состояние
	IsLoggedIn    bool
	IsDarkMode    bool
	IsNewUser     bool
	IsUnlocked    bool
	PasswordError string

	// Уведомления
	CopyNotification     string
	CopyNotificationTime time.Time

	// Раскрытый контакт (для меню)
	ExpandedContact string

	mu sync.Mutex
}

// ContactWidgets - виджеты для одного контакта
type ContactWidgets struct {
	ClickMain       widget.Clickable
	ClickAccept     widget.Clickable
	ClickDecline    widget.Clickable
	ClickDisconnect widget.Clickable
	ClickRemove     widget.Clickable
	ClickMenu       widget.Clickable
}

// MyNodeInfo - информация о текущем пользователе
type MyNodeInfo struct {
	Nick         string
	PeerID       string
	Fingerprint  string
	PeersCount   int
	HasRelay     bool
	AddFriendCmd string
}

// UIMessage - сообщение в чате
type UIMessage struct {
	Sender string
	Text   string
	Time   time.Time
}

// NewUIState создаёт новое состояние
func NewUIState() *UIState {
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

	state.InputMsg.SingleLine = false
	state.LoginNick.SingleLine = true
	state.AddNick.SingleLine = true
	state.AddID.SingleLine = true
	state.AddKey.SingleLine = true

	return state
}

// updateNodeData обновляет данные из ноды
func updateNodeData(s *UIState, node *f2f.Node) {
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