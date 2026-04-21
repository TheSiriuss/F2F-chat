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
	// HintFile stores an optional plaintext password hint. Shown on failed
	// login. Stored in plaintext by design — anyone with disk access can
	// read it, which is acceptable for a hint.
	HintFile = "password.hint"
)

const (
	// MinRecommendedPasswordLen is a soft recommendation, not an enforced minimum.
	MinRecommendedPasswordLen = 12
	// MaxHintLength caps the plaintext hint to avoid unbounded disk writes.
	MaxHintLength = 256
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

const (
	// Skipped ratchet keys older than this are purged, bounding memory
	// growth on long sessions and limiting the window an attacker with
	// a leaked chain can exploit stored keys.
	MaxSkipKeyAge = 1 * time.Hour
	// Minimum gap between accepted incoming handshakes per contact.
	HandshakeCooldown = 500 * time.Millisecond

	// Maximum multiaddrs we cache per contact. Most-recent-first; older
	// entries drop off the tail when this limit is exceeded.
	MaxKnownAddrsPerContact = 30

	// ---- Voice call settings ----
	// AudioProtocolID is the separate libp2p stream used for raw voice data.
	AudioProtocolID = "/f2f-chat/audio/1.0"
	// VideoProtocolID carries ASCII-rendered video frames.
	VideoProtocolID = "/f2f-chat/video/1.0"
	// CallSampleRate — 48 kHz fullband, Opus's native rate. Voice sounds
	// markedly more natural than wideband (16 kHz), especially for sibilants.
	CallSampleRate  = 48000
	CallChannels    = 1
	CallFrameMs     = 20                                    // each Opus frame = 20 ms
	CallSamplesPerFrame = CallSampleRate * CallFrameMs / 1000 // 960
	// Opus bitrate — 48 kbit/s mono fullband is "transparent" voice quality
	// per Opus recommendations (good for narration, singing, music tolerable).
	CallOpusBitrate = 48000
	// HolePunchWaitTimeout — how long the call initiator waits for
	// DCUtR (hole-punch) to upgrade a Limited (relay) connection to
	// direct before giving up and REFUSING the call. Calls over relay
	// would die at ~25 s due to circuit-v2's 128 KiB cap; we'd rather
	// fail fast with a clear error than ship a broken experience.
	HolePunchWaitTimeout = 8 * time.Second
	// Opus encoder complexity (0-10). 10 = max quality, still tiny CPU.
	CallOpusComplexity = 10
	// Hint to Opus about expected packet loss. Tells encoder to be more
	// resilient (adds redundancy when combined with InbandFEC). ~3% is
	// typical for P2P over residential internet.
	CallOpusExpectedLossPct = 3
	// CallJitterFrames is the playback buffer depth. 3 × 20 ms = 60 ms —
	// enough to absorb typical P2P jitter without adding audible delay.
	CallJitterFrames = 3
	// CallOfferTimeout — how long the caller rings before auto-hangup.
	// Symmetric: also drops a CallIncoming state after this window so the
	// callee isn't stuck with a phantom ringing indicator if the caller
	// disappeared without sending MsgTypeCallEnd.
	CallOfferTimeout = 45 * time.Second
	// Minimum gap between accepted CallOffer events from the same peer.
	// Works like HandshakeCooldown for the voice-call control plane.
	CallOfferMinInterval = 2 * time.Second
	// Rotate per-direction call AEAD keys every this many frames. Provides
	// intra-call forward secrecy: a memory-dump at frame N can't decrypt
	// frames from before N/CallKeyRotateInterval*CallKeyRotateInterval.
	// 250 frames × 20 ms = 5-second rotation window.
	CallKeyRotateInterval = 250
	// How often the call initiator performs a DH ratchet step for
	// Post-Compromise Security. Fresh X25519 ephemeral → fresh shared →
	// mixed into both voice and video keys via HKDF. Attacker with a
	// single-snapshot memory leak loses decrypt ability after one interval.
	CallRatchetInterval = 30 * time.Second
)

// --- Timeouts ---

const (
	PeerLookupTimeout  = 45 * time.Second
	PresenceTimeout    = 15 * time.Second
	PresenceInterval   = 30 * time.Second
	AdvertiseDelay     = 5 * time.Second
	KeepAliveInterval  = 30 * time.Second
	// Libp2pKeepAliveInterval — how often we ping every direct-connected
	// contact at the libp2p transport layer. Shorter than typical UDP
	// NAT mapping timeouts (~30 s on home routers) so mappings stay
	// alive and the direct connection doesn't silently degrade to relay.
	Libp2pKeepAliveInterval = 20 * time.Second
	AdvertiseInterval  = 1 * time.Minute
	StreamReadTimeout  = 10 * time.Minute
	HandshakeTimeout   = 10 * time.Second
	WriteTimeout       = 60 * time.Second
	BootstrapTimeout   = 15 * time.Second
	MaxTimeSkew        = 2 * time.Minute
	NewStreamTimeout   = 30 * time.Second
	// AddrCacheDialTimeout caps the "try cached addresses first" phase of
	// InitConnect. Cache hits dial in <1s — so a short timeout means stale
	// cached entries fail fast and we fall through to DHT instead of making
	// the user wait 30s while libp2p exhausts dead addrs.
	AddrCacheDialTimeout = 6 * time.Second
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
