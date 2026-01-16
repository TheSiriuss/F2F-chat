package main

import (
	"os"
	"runtime"
	"time"
)

// --- Version & Protocol ---

const (
	ProtocolVersion  = "1.1.0-alpha"
	ProtocolID       = "/f2f-chat/1.1.0"
	RendezvousString = "f2f-chat-alpha-v1"
	ContactsFile     = "contacts.json"
	IdentityFile     = "identity.json"
)

// --- Limits ---

const (
	HandshakeLimit = 4096
	MaxNickLength  = 32
	MaxMsgLength   = 1000
	MaxMessageSize = 64 * 1024
)

// --- Timeouts ---

const (
	PeerLookupTimeout  = 45 * time.Second
	PresenceTimeout    = 15 * time.Second
	PresenceInterval   = 30 * time.Second
	AdvertiseDelay     = 5 * time.Second
	KeepAliveInterval  = 30 * time.Second
	AdvertiseInterval  = 1 * time.Minute
	StreamReadTimeout  = 10 * time.Minute
	HandshakeTimeout   = 10 * time.Second
	WriteTimeout       = 5 * time.Second
	BootstrapTimeout   = 15 * time.Second
	MaxTimeSkew        = 2 * time.Minute
	NewStreamTimeout   = 30 * time.Second
	ReconnectCooldown  = 3 * time.Second
	ShutdownTimeout    = 3 * time.Second
	MaxPresenceBackoff = 15 * time.Minute
)

// --- Limits ---

const (
	PresenceMaxWorkers  = 3
	MaxNoncesPerContact = 100
)

// --- Debug ---

var DebugMode = false

// --- UI Style ---

type UIStyle struct {
	TopLeft, TopRight, BottomLeft, BottomRight string
	Horizontal, Vertical, TeeLeft, TeeRight    string
	Online, Offline, InChat, Connected         string
	Pending, Global, Searching, Unknown        string
	OK, Fail, Warning, Info, Arrow, Bell, Mail string
}

var Style UIStyle

func initStyle() {
	useUnicode := runtime.GOOS != "windows"
	if os.Getenv("F2F_ASCII") == "1" {
		useUnicode = false
	}
	if os.Getenv("F2F_UNICODE") == "1" {
		useUnicode = true
	}

	if useUnicode {
		Style = UIStyle{
			TopLeft: "┌", TopRight: "┐", BottomLeft: "└", BottomRight: "┘",
			Horizontal: "─", Vertical: "│", TeeLeft: "├", TeeRight: "┤",
			Online: "[*]", Offline: "[-]", InChat: "[#]", Connected: "[+]",
			Pending: "[~]", Global: "[G]", Searching: "[?]", Unknown: "[.]",
			OK: "[+]", Fail: "[!]", Warning: "[!]", Info: "[i]",
			Arrow: "->", Bell: "[!]", Mail: "[>]",
		}
	} else {
		Style = UIStyle{
			TopLeft: "+", TopRight: "+", BottomLeft: "+", BottomRight: "+",
			Horizontal: "-", Vertical: "|", TeeLeft: "+", TeeRight: "+",
			Online: "[*]", Offline: "[-]", InChat: "[#]", Connected: "[+]",
			Pending: "[~]", Global: "[G]", Searching: "[?]", Unknown: "[.]",
			OK: "[+]", Fail: "[X]", Warning: "[!]", Info: "[i]",
			Arrow: "->", Bell: "[!]", Mail: "[>]",
		}
	}
}
