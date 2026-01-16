package main

import (
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

// --- Enums ---

type ChatState int

const (
	StateIdle ChatState = iota
	StatePending
	StateActive
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
	MsgTypeText      = "txt"
	MsgTypePing      = "png"
	MsgTypeBye       = "bye"
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
