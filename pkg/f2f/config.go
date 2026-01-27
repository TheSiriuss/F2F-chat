package f2f

import (
	"time"
)

// --- Version & Protocol ---

const (
	ProtocolVersion  = "1.4.0-ratchet" // Bump version
	ProtocolID       = "/f2f-chat/1.4.0"
	RendezvousString = "f2f-chat-bin-v1"
	ContactsFile     = "contacts.dat"
	IdentityFile     = "identity.dat"
)

// --- Limits ---

const (
	HandshakeLimit = 4096
	MaxNickLength  = 32
	MaxMsgLength   = 4000
	MaxFrameSize   = 64 * 1024 * 1024
	FileChunkSize  = 256 * 1024
	MaxSkipKeys    = 500 // Сколько ключей хранить для out-of-order сообщений
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
	WriteTimeout       = 60 * time.Second
	BootstrapTimeout   = 15 * time.Second
	MaxTimeSkew        = 2 * time.Minute
	NewStreamTimeout   = 30 * time.Second
	ReconnectCooldown  = 3 * time.Second
	ShutdownTimeout    = 3 * time.Second
	MaxPresenceBackoff = 15 * time.Minute
	FileOfferTimeout   = 10 * time.Minute
)

// --- Ratchet KDF Info ---
// Используются для разделения контекстов HKDF
var (
	InfoRootKey  = []byte("F2F-Ratchet-Root")
	InfoChainKey = []byte("F2F-Ratchet-Chain")
	InfoMsgKey   = []byte("F2F-Ratchet-Msg")
)

// --- Limits ---

const (
	PresenceMaxWorkers  = 3
	MaxNoncesPerContact = 100
)

// --- Debug ---

var DebugMode = false
