package f2f

import (
	"time"
)

// --- Version & Protocol ---

const (
	ProtocolVersion  = "1.2.0-alpha"
	ProtocolID       = "/f2f-chat/1.2.0"
	RendezvousString = "f2f-chat-alpha-v1"
	ContactsFile     = "contacts.json"
	IdentityFile     = "identity.json"
)

// --- Limits ---

const (
	HandshakeLimit = 4096
	MaxNickLength  = 32
	MaxMsgLength   = 4000             // Увеличено с 1000
	MaxFrameSize   = 64 * 1024 * 1024 // 64 MB для чанков
	FileChunkSize  = 256 * 1024       // 256 KB чанки
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
	WriteTimeout       = 60 * time.Second // Увеличено для больших файлов
	BootstrapTimeout   = 15 * time.Second
	MaxTimeSkew        = 2 * time.Minute
	NewStreamTimeout   = 30 * time.Second
	ReconnectCooldown  = 3 * time.Second
	ShutdownTimeout    = 3 * time.Second
	MaxPresenceBackoff = 15 * time.Minute
	FileOfferTimeout   = 10 * time.Minute // Сколько ждать ответа на предложение
)

// --- Limits ---

const (
	PresenceMaxWorkers  = 3
	MaxNoncesPerContact = 100
)

// --- Debug ---

var DebugMode = false
