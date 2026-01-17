package f2f

import (
	"context"
	"hash"
	"os"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

// --- Enums ---

type ChatState int

const (
	StateIdle            ChatState = iota
	StatePendingIncoming           // Мне прислали запрос
	StatePendingOutgoing           // Я отправил запрос
	StateActive                    // Чат активен
)

type PresenceStatus int

const (
	PresenceUnknown PresenceStatus = iota
	PresenceOnline
	PresenceOffline
	PresenceChecking
)

func (p PresenceStatus) String() string {
	switch p {
	case PresenceOnline:
		return "ONLINE"
	case PresenceOffline:
		return "OFFLINE"
	case PresenceChecking:
		return "CHECKING..."
	default:
		return "UNKNOWN"
	}
}

// --- Message Types ---

const (
	MsgTypeHandshake = "hs"
	MsgTypeRequest   = "req"
	MsgTypeAccept    = "acc"
	MsgTypeDecline   = "dec"
	MsgTypeCancel    = "can"
	MsgTypeText      = "txt"
	MsgTypePing      = "png"
	MsgTypeBye       = "bye"

	// File transfer messages
	MsgTypeFileOffer   = "fo"
	MsgTypeFileAccept  = "fa"
	MsgTypeFileDecline = "fd"
	MsgTypeFileCancel  = "fc"
	MsgTypeFileChunk   = "fch"
	MsgTypeFileDone    = "fdn"
)

// --- Protocol Messages ---

type InnerMessage struct {
	Type      string `json:"t"`
	Timestamp int64  `json:"ts"`
	Content   string `json:"c,omitempty"`
}

type HandshakePayload struct {
	Version      string `json:"v"`
	Timestamp    int64  `json:"ts"`
	Nonce        int64  `json:"n"`
	NaClPubKey   []byte `json:"key"`
	EphemeralPub []byte `json:"eph"`
	Signature    []byte `json:"sig"`
}

// --- File Transfer Types ---

type FileOffer struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Size int64  `json:"size"`
}

type FileResponse struct {
	ID string `json:"id"`
}

type FileChunk struct {
	ID    string `json:"id"`
	Index int    `json:"i"`
	Total int    `json:"t"`
	Data  string `json:"d"` // base64
}

type FileDone struct {
	ID   string `json:"id"`
	Hash string `json:"h"` // sha256 hex
}

type FileTransfer struct {
	ID          string
	Name        string
	Size        int64
	FilePath    string    // для исходящих - путь к файлу
	TempPath    string    // для входящих - путь к temp файлу
	TempFile    *os.File  // для входящих - открытый temp файл
	Hasher      hash.Hash // для вычисления хеша по ходу
	Received    int64     // байт получено
	ChunksSent  int
	ChunksRecv  int
	TotalChunks int
	CreatedAt   time.Time
	IsOutgoing  bool
	Cancelled   bool
}

// --- Contact ---

type Contact struct {
	Nickname    string   `json:"nick"`
	PeerID      peer.ID  `json:"pid"`
	PublicKey   [32]byte `json:"pub"`
	LastMsgTime int64    `json:"-"`

	SeenNonces map[int64]time.Time `json:"-"`

	State           ChatState      `json:"-"`
	Stream          network.Stream `json:"-"`
	Connecting      bool           `json:"-"`
	LastConnectTime time.Time      `json:"-"`

	// Контекст для отмены connecting
	connectCtx    context.Context    `json:"-"`
	connectCancel context.CancelFunc `json:"-"`

	Presence      PresenceStatus `json:"-"`
	LastSeen      time.Time      `json:"-"`
	LastChecked   time.Time      `json:"-"`
	AddressCount  int            `json:"-"`
	FailCount     int            `json:"-"`
	NextCheckTime time.Time      `json:"-"`

	// Forward Secrecy keys
	localEphPriv *[32]byte `json:"-"`
	localEphPub  *[32]byte `json:"-"`
	remoteEphPub *[32]byte `json:"-"`
	sessionKey   *[32]byte `json:"-"`
	sessionEstab bool      `json:"-"`

	// File transfer (один файл за раз)
	PendingFile *FileTransfer `json:"-"`

	mu      sync.Mutex `json:"-"`
	writeMu sync.Mutex `json:"-"`
}

// --- Identity ---

type LocalIdentity struct {
	Nickname   string `json:"nick"`
	LibP2PPriv []byte `json:"libp2p_priv"`
	NaClPub    []byte `json:"nacl_pub"`
	NaClPriv   []byte `json:"nacl_priv"`
}
