package f2f

import (
	"context"
	"encoding/binary"
	"hash"
	"io"
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

// --- Frame Types ---

const (
	FrameTypeMsg    byte = 0x00
	FrameTypeBinary byte = 0x01
)

// --- Message Types ---

type MessageType int

const (
	MsgTypeHandshake MessageType = iota
	MsgTypeRequest
	MsgTypeAccept
	MsgTypeDecline
	MsgTypeCancel
	MsgTypeText
	MsgTypePing
	MsgTypeBye

	// PCS / Ratchet messages
	// MsgTypeRekey и MsgTypeRekeyAck УДАЛЕНЫ, так как Double Ratchet встроен в протокол

	// File transfer messages
	MsgTypeFileOffer
	MsgTypeFileAccept
	MsgTypeFileDecline
	MsgTypeFileCancel
	MsgTypeFileDone
)

// --- Serialization Helpers ---
// (Buffer implementation omitted for brevity - same as before)
type Buffer struct {
	data   []byte
	offset int
}

func NewBuffer(data []byte) *Buffer {
	return &Buffer{data: data, offset: 0}
}

func (b *Buffer) WriteByte(v byte) {
	b.data = append(b.data, v)
}

func (b *Buffer) WriteUint32(v uint32) {
	tmp := make([]byte, 4)
	binary.BigEndian.PutUint32(tmp, v)
	b.data = append(b.data, tmp...)
}

func (b *Buffer) WriteInt64(v int64) {
	tmp := make([]byte, 8)
	binary.BigEndian.PutUint64(tmp, uint64(v))
	b.data = append(b.data, tmp...)
}

func (b *Buffer) WriteBytes(v []byte) {
	b.WriteUint32(uint32(len(v)))
	b.data = append(b.data, v...)
}

func (b *Buffer) WriteString(v string) {
	b.WriteBytes([]byte(v))
}

func (b *Buffer) WriteFixed32(v [32]byte) {
	b.data = append(b.data, v[:]...)
}

func (b *Buffer) ReadByte() (byte, error) {
	if b.offset >= len(b.data) {
		return 0, io.ErrUnexpectedEOF
	}
	v := b.data[b.offset]
	b.offset++
	return v, nil
}

func (b *Buffer) ReadUint32() (uint32, error) {
	if b.offset+4 > len(b.data) {
		return 0, io.ErrUnexpectedEOF
	}
	v := binary.BigEndian.Uint32(b.data[b.offset:])
	b.offset += 4
	return v, nil
}

func (b *Buffer) ReadInt64() (int64, error) {
	if b.offset+8 > len(b.data) {
		return 0, io.ErrUnexpectedEOF
	}
	v := int64(binary.BigEndian.Uint64(b.data[b.offset:]))
	b.offset += 8
	return v, nil
}

func (b *Buffer) ReadBytes() ([]byte, error) {
	l, err := b.ReadUint32()
	if err != nil {
		return nil, err
	}
	if b.offset+int(l) > len(b.data) {
		return nil, io.ErrUnexpectedEOF
	}
	v := make([]byte, l)
	copy(v, b.data[b.offset:b.offset+int(l)])
	b.offset += int(l)
	return v, nil
}

func (b *Buffer) ReadString() (string, error) {
	bs, err := b.ReadBytes()
	if err != nil {
		return "", err
	}
	return string(bs), nil
}

func (b *Buffer) ReadFixed32() ([32]byte, error) {
	var out [32]byte
	if b.offset+32 > len(b.data) {
		return out, io.ErrUnexpectedEOF
	}
	copy(out[:], b.data[b.offset:b.offset+32])
	b.offset += 32
	return out, nil
}

func (b *Buffer) Bytes() []byte {
	return b.data
}

// --- Protocol Messages ---

type InnerMessage struct {
	Type      MessageType
	Timestamp int64
	Content   string
	Payload   []byte
}

func (m *InnerMessage) Marshal() []byte {
	b := NewBuffer(make([]byte, 0, 128))
	b.WriteUint32(uint32(m.Type))
	b.WriteInt64(m.Timestamp)
	b.WriteString(m.Content)
	b.WriteBytes(m.Payload)
	return b.Bytes()
}

func (m *InnerMessage) Unmarshal(data []byte) error {
	b := NewBuffer(data)
	t, err := b.ReadUint32()
	if err != nil {
		return err
	}
	m.Type = MessageType(t)
	m.Timestamp, err = b.ReadInt64()
	if err != nil {
		return err
	}
	m.Content, err = b.ReadString()
	if err != nil {
		return err
	}
	m.Payload, err = b.ReadBytes()
	return err
}

type HandshakePayload struct {
	Version      string
	Timestamp    int64
	Nonce        int64
	NaClPubKey   []byte
	EphemeralPub []byte
	Signature    []byte
}

func (h *HandshakePayload) Marshal() []byte {
	b := NewBuffer(make([]byte, 0, 256))
	b.WriteString(h.Version)
	b.WriteInt64(h.Timestamp)
	b.WriteInt64(h.Nonce)
	b.WriteBytes(h.NaClPubKey)
	b.WriteBytes(h.EphemeralPub)
	b.WriteBytes(h.Signature)
	return b.Bytes()
}

func (h *HandshakePayload) Unmarshal(data []byte) error {
	b := NewBuffer(data)
	var err error
	h.Version, err = b.ReadString()
	if err != nil {
		return err
	}
	h.Timestamp, err = b.ReadInt64()
	if err != nil {
		return err
	}
	h.Nonce, err = b.ReadInt64()
	if err != nil {
		return err
	}
	h.NaClPubKey, err = b.ReadBytes()
	if err != nil {
		return err
	}
	h.EphemeralPub, err = b.ReadBytes()
	if err != nil {
		return err
	}
	h.Signature, err = b.ReadBytes()
	return err
}

// --- Double Ratchet Structures ---

// RatchetHeader отправляется с каждым зашифрованным сообщением
type RatchetHeader struct {
	PublicKey [32]byte // Текущий DH ключ отправителя
	PN        uint32   // Количество сообщений в предыдущей цепочке
	N         uint32   // Номер сообщения в текущей цепочке
}

func (rh *RatchetHeader) Marshal() []byte {
	// Fixed size: 32 + 4 + 4 = 40 bytes
	buf := make([]byte, 40)
	copy(buf[0:32], rh.PublicKey[:])
	binary.BigEndian.PutUint32(buf[32:36], rh.PN)
	binary.BigEndian.PutUint32(buf[36:40], rh.N)
	return buf
}

func (rh *RatchetHeader) Unmarshal(data []byte) error {
	if len(data) < 40 {
		return io.ErrUnexpectedEOF
	}
	copy(rh.PublicKey[:], data[0:32])
	rh.PN = binary.BigEndian.Uint32(data[32:36])
	rh.N = binary.BigEndian.Uint32(data[36:40])
	return nil
}

// SkippedKey хранит ключи для пропущенных сообщений (out-of-order)
type SkippedKey struct {
	Key       [32]byte
	Timestamp time.Time
}

// RatchetState хранит состояние Double Ratchet
type RatchetState struct {
	// KDF Chains
	RootKey   [32]byte
	ChainKeyS [32]byte // Sending chain key
	ChainKeyR [32]byte // Receiving chain key

	// DH Ratchet
	DHLocalPriv *[32]byte
	DHLocalPub  *[32]byte
	DHRemotePub *[32]byte // Последний известный ключ собеседника

	// Counts
	Ns uint32 // Sending message number
	Nr uint32 // Receiving message number
	PN uint32 // Count of previous receiving chain

	// Skipped Message Keys for handling out-of-order messages
	// Map: HeaderKey(Pub+N) -> MessageKey
	SkippedMsgKeys map[[36]byte]SkippedKey
}

// --- File Transfer Types ---

type FileOffer struct {
	ID   string
	Name string
	Size int64
}

func (f *FileOffer) Marshal() []byte {
	b := NewBuffer(make([]byte, 0, 64))
	b.WriteString(f.ID)
	b.WriteString(f.Name)
	b.WriteInt64(f.Size)
	return b.Bytes()
}

func (f *FileOffer) Unmarshal(data []byte) error {
	b := NewBuffer(data)
	var err error
	f.ID, err = b.ReadString()
	if err != nil {
		return err
	}
	f.Name, err = b.ReadString()
	if err != nil {
		return err
	}
	f.Size, err = b.ReadInt64()
	return err
}

type FileResponse struct {
	ID string
}

func (f *FileResponse) Marshal() []byte {
	b := NewBuffer(make([]byte, 0, 32))
	b.WriteString(f.ID)
	return b.Bytes()
}

func (f *FileResponse) Unmarshal(data []byte) error {
	b := NewBuffer(data)
	var err error
	f.ID, err = b.ReadString()
	return err
}

// BinaryChunkHeader - заголовок бинарного чанка
type BinaryChunkHeader struct {
	FileID [16]byte
	Index  uint32
	Total  uint32
}

const BinaryChunkHeaderSize = 16 + 4 + 4 // 24 bytes

type FileDone struct {
	ID   string
	Hash string // sha256 hex
}

func (f *FileDone) Marshal() []byte {
	b := NewBuffer(make([]byte, 0, 64))
	b.WriteString(f.ID)
	b.WriteString(f.Hash)
	return b.Bytes()
}

func (f *FileDone) Unmarshal(data []byte) error {
	b := NewBuffer(data)
	var err error
	f.ID, err = b.ReadString()
	if err != nil {
		return err
	}
	f.Hash, err = b.ReadString()
	return err
}

type FileTransfer struct {
	ID          string
	IDBinary    [16]byte
	Name        string
	Size        int64
	FilePath    string
	TempPath    string
	TempFile    *os.File
	Hasher      hash.Hash
	Received    int64
	ChunksSent  int
	ChunksRecv  int
	TotalChunks int
	CreatedAt   time.Time
	IsOutgoing  bool
	Cancelled   bool
}

// --- Contact ---

type Contact struct {
	Nickname    string
	PeerID      peer.ID
	PublicKey   [32]byte
	LastMsgTime int64

	SeenNonces map[int64]time.Time

	State           ChatState
	Stream          network.Stream
	Connecting      bool
	LastConnectTime time.Time

	connectCtx    context.Context
	connectCancel context.CancelFunc

	Presence      PresenceStatus
	LastSeen      time.Time
	LastChecked   time.Time
	AddressCount  int
	FailCount     int
	NextCheckTime time.Time

	// Double Ratchet State
	// Заменяет простые sessionKey
	Ratchet      *RatchetState
	sessionEstab bool

	// Ephemeral keys for initial handshake only
	handshakePriv *[32]byte
	handshakePub  *[32]byte

	PendingFile *FileTransfer

	mu      sync.Mutex
	writeMu sync.Mutex
}

// --- Identity ---

type LocalIdentity struct {
	Nickname   string
	LibP2PPriv []byte
	NaClPub    []byte
	NaClPriv   []byte
}

func (id *LocalIdentity) Marshal() []byte {
	b := NewBuffer(make([]byte, 0, 512))
	b.WriteString(id.Nickname)
	b.WriteBytes(id.LibP2PPriv)
	b.WriteBytes(id.NaClPub)
	b.WriteBytes(id.NaClPriv)
	return b.Bytes()
}

func (id *LocalIdentity) Unmarshal(data []byte) error {
	b := NewBuffer(data)
	var err error
	id.Nickname, err = b.ReadString()
	if err != nil {
		return err
	}
	id.LibP2PPriv, err = b.ReadBytes()
	if err != nil {
		return err
	}
	id.NaClPub, err = b.ReadBytes()
	if err != nil {
		return err
	}
	id.NaClPriv, err = b.ReadBytes()
	return err
}

type SerializableContact struct {
	Nickname  string
	PeerID    string
	PublicKey [32]byte
}

func MarshalContacts(contacts []SerializableContact) []byte {
	b := NewBuffer(make([]byte, 0, 1024))
	b.WriteUint32(uint32(len(contacts)))
	for _, c := range contacts {
		b.WriteString(c.Nickname)
		b.WriteString(c.PeerID)
		b.WriteFixed32(c.PublicKey)
	}
	return b.Bytes()
}

func UnmarshalContacts(data []byte) ([]SerializableContact, error) {
	b := NewBuffer(data)
	count, err := b.ReadUint32()
	if err != nil {
		return nil, err
	}
	contacts := make([]SerializableContact, count)
	for i := uint32(0); i < count; i++ {
		contacts[i].Nickname, err = b.ReadString()
		if err != nil {
			return nil, err
		}
		contacts[i].PeerID, err = b.ReadString()
		if err != nil {
			return nil, err
		}
		contacts[i].PublicKey, err = b.ReadFixed32()
		if err != nil {
			return nil, err
		}
	}
	return contacts, nil
}
