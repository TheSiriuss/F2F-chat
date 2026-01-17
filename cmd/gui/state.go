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
	FilePath        widget.Editor // Путь к файлу для отправки

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

	// Файловые кнопки
	BtnSendFile    widget.Clickable
	BtnAcceptFile  widget.Clickable
	BtnDeclineFile widget.Clickable
	BtnCancelFile  widget.Clickable

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

	// Состояние файловой передачи
	FileTransfer *FileTransferUI

	mu sync.Mutex
}

// FileTransferUI - состояние UI для передачи файлов
type FileTransferUI struct {
	// Входящее предложение
	HasIncoming  bool
	IncomingNick string
	IncomingName string
	IncomingSize int64

	// Активная передача
	IsActive   bool
	IsUpload   bool // true = отправляем, false = получаем
	FileName   string
	Progress   float64 // 0.0 - 1.0
	StatusText string

	// Результат
	ShowResult    bool
	ResultSuccess bool
	ResultMessage string
	ResultTime    time.Time
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
	Sender   string
	Text     string
	Time     time.Time
	IsFile   bool   // Это сообщение о файле
	FileName string // Имя файла (если IsFile)
}

// NewUIState создаёт новое состояние
func NewUIState() *UIState {
	state := &UIState{
		MatTheme:     material.NewTheme(),
		Theme:        &LightTheme,
		BtnContacts:  make(map[string]*ContactWidgets),
		IsDarkMode:   false,
		IsNewUser:    f2f.IsNewUser(),
		IsUnlocked:   false,
		FileTransfer: &FileTransferUI{},
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
	state.FilePath.SingleLine = true

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

	// Очищаем результат через 5 секунд
	if s.FileTransfer.ShowResult && time.Since(s.FileTransfer.ResultTime) > 5*time.Second {
		s.FileTransfer.ShowResult = false
	}
}
