package f2f

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/multiformats/go-multiaddr"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"crypto/sha256"

	"github.com/gen2brain/malgo"
)

// notifyCallIncoming / Outgoing / Active / Ended fire the optional
// CallListener interface if the attached listener implements it. Keeps
// call.go agnostic of UI — a plain OnLog-only listener still works.
// waitForDirectUpgrade tries HARD to get a direct (non-relay) connection
// to pid within `budget`. Strategy:
//
//  1. Poll existing ConnsToPeer — maybe DCUtR already upgraded.
//  2. Refresh addresses from DHT (fresh peer record, maybe new public addrs).
//  3. For every non-circuit addr, attempt a forced direct dial in
//     parallel — libp2p's ForceDirectDial context bypasses the
//     "already have a limited conn" short-circuit in the connection
//     manager, so a NEW direct conn can be opened alongside the
//     existing relay one.
//  4. Keep polling until the deadline.
//
// Returns true as soon as any direct connection materialises.
func (n *Node) waitForDirectUpgrade(pid peer.ID, budget time.Duration) bool {
	if n.hasDirectConn(pid) {
		return true
	}

	deadline := time.Now().Add(budget)

	// Kick off a DHT refresh + force-dial attempt in the background so
	// polling and dialing race each other.
	go n.forceDirectDial(pid)

	for time.Now().Before(deadline) {
		if n.hasDirectConn(pid) {
			n.Log(LogLevelInfo, "[call] direct-соединение установлено (relay обойдён)")
			return true
		}
		time.Sleep(150 * time.Millisecond)
	}
	n.Log(LogLevelWarning, "[call] прямое соединение не установлено — вероятно симметричный NAT с обеих сторон")
	return false
}

// hasDirectConn reports whether any active connection to pid is NOT a
// circuit (i.e. a direct transport connection).
func (n *Node) hasDirectConn(pid peer.ID) bool {
	for _, c := range n.host.Network().ConnsToPeer(pid) {
		if !strings.Contains(c.RemoteMultiaddr().String(), "p2p-circuit") {
			return true
		}
	}
	return false
}

// forceDirectDial refreshes addresses from DHT and then explicitly
// attempts a direct dial to each non-circuit address. Uses
// network.WithForceDirectDial so libp2p's connection manager doesn't
// just return the existing Limited conn. Runs synchronously; caller
// should invoke in a goroutine for race-with-polling semantics.
func (n *Node) forceDirectDial(pid peer.ID) {
	// Refresh addresses via DHT — the peer's circulating PeerRecord may
	// already list newly-opened direct listen addresses.
	if n.dht != nil {
		ctx, cancel := context.WithTimeout(n.ctx, 8*time.Second)
		if info, err := n.dht.FindPeer(ctx, pid); err == nil {
			n.host.Peerstore().AddAddrs(pid, info.Addrs, peerstore.AddressTTL)
		}
		cancel()
	}

	addrs := n.host.Peerstore().Addrs(pid)
	var direct []multiaddr.Multiaddr
	for _, a := range addrs {
		if !strings.Contains(a.String(), "p2p-circuit") {
			direct = append(direct, a)
		}
	}
	if len(direct) == 0 {
		return
	}

	// Try each addr individually — libp2p sometimes short-circuits on
	// the first failure if we bundle them.
	for _, a := range direct {
		select {
		case <-n.ctx.Done():
			return
		default:
		}
		ctx, cancel := context.WithTimeout(n.ctx, 3*time.Second)
		ctx = network.WithForceDirectDial(ctx, "f2f-call-force")
		_ = n.host.Connect(ctx, peer.AddrInfo{ID: pid, Addrs: []multiaddr.Multiaddr{a}})
		cancel()
		if n.hasDirectConn(pid) {
			return
		}
	}
}

// classifyCallEndReason maps an audio-stream read error to a short human
// reason for the UI banner. Relay-limit resets produce very specific
// error substrings; everything else is a generic hangup/disconnect.
func classifyCallEndReason(err error) string {
	if err == nil {
		return "вызов завершён"
	}
	msg := err.Error()
	switch {
	case containsAny(msg, "resource limit", "limit exceeded", "limited conn", "resource limit exceeded"):
		return "relay-бюджет исчерпан (видео+аудио превысили лимит relay'я)"
	case containsAny(msg, "stream reset"):
		return "собеседник сбросил стрим"
	case containsAny(msg, "connection closed", "connection reset"):
		return "соединение разорвано"
	case containsAny(msg, "EOF"):
		return "собеседник завершил вызов"
	case containsAny(msg, "deadline exceeded", "timeout"):
		return "таймаут чтения (собеседник молчит)"
	default:
		return "разрыв связи"
	}
}

// containsAny reports whether s contains any of the substrings.
func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(sub) > 0 && bytes.Contains([]byte(s), []byte(sub)) {
			return true
		}
	}
	return false
}

func (n *Node) notifyCallIncoming(pid peer.ID, nick, kind string) {
	if cl, ok := n.listener.(CallListener); ok {
		cl.OnCallIncoming(pid.String(), nick, kind)
	}
}
func (n *Node) notifyCallOutgoing(pid peer.ID, nick, kind string) {
	if cl, ok := n.listener.(CallListener); ok {
		cl.OnCallOutgoing(pid.String(), nick, kind)
	}
}
func (n *Node) notifyCallActive(pid peer.ID, nick, kind string) {
	if cl, ok := n.listener.(CallListener); ok {
		cl.OnCallActive(pid.String(), nick, kind)
	}
}
func (n *Node) notifyCallEnded(pid peer.ID, nick, reason, duration string) {
	if cl, ok := n.listener.(CallListener); ok {
		cl.OnCallEnded(pid.String(), nick, reason, duration)
	}
}

// -----------------------------------------------------------------------------
// CallSession — per-call runtime state
// -----------------------------------------------------------------------------

type CallSession struct {
	State CallState

	// Freshly generated per-call X25519 ephemeral keys.
	localPriv *[32]byte
	localPub  *[32]byte

	// Directional encryption keys (derived on Accept from ECDH shared secret).
	// Each side uses sendKey to encrypt outgoing frames and recvKey (which
	// equals the peer's sendKey) to decrypt incoming frames.
	//
	// These get ratcheted forward every CallKeyRotateInterval frames via
	// HKDF for in-call forward secrecy — so a mid-call key leak can't decrypt
	// earlier portions. sendGen/recvGen track which "generation" the current
	// key value corresponds to.
	sendKey [32]byte
	recvKey [32]byte
	sendGen uint64
	recvGen uint64

	// Monotonic send counter — used as the XChaCha20 nonce for each outgoing
	// audio frame. Incrementing independently of the receive side means the
	// (key, nonce) pair never repeats within one call.
	sendCtr uint64

	// Highest receive counter seen so far. Frames with counter <= seenCtr are
	// rejected as replays. Late frames (within jitter window) are accepted
	// because of how we track last-max rather than a per-counter set.
	recvCtr uint64

	// Audio libp2p stream used only for voice frames.
	stream network.Stream

	// Cancellation hooks for capture + playback goroutines.
	stopCh chan struct{}
	once   sync.Once

	// Audio devices opened for the duration of the call.
	captureDevice  *malgo.Device
	playbackDevice *malgo.Device

	// Opus codecs (per call — Opus state is stateful between frames).
	encoder *opusEncoder
	decoder *opusDecoder

	// Jitter buffer: a simple ring of decoded PCM frames ready to be pulled
	// by the malgo playback callback. Accessed under jitterMu.
	jitter   [][]int16
	jitterMu sync.Mutex
	// lastFrame keeps the last successfully decoded frame so the playback
	// callback can fall back to it (or silence) when the buffer is empty.
	lastFrame []int16

	// captureDrain lets the capture loop pull a full 20ms frame of PCM
	// samples from the capture ring buffer (nil until devices are opened).
	captureDrain func() []int16

	// DHRemotePubForSetup holds the peer's X25519 ephemeral pubkey after we
	// receive a CallOffer (pre-accept). Cleared once keys are derived.
	DHRemotePubForSetup *[32]byte

	// isInitiator records whether we placed this call. Only the initiator
	// drives the periodic DH ratchet — keeps the protocol simple and
	// sufficient for PCS (one-sided rotation heals both parties' key
	// material after one round).
	isInitiator bool

	// DH ratchet state for Post-Compromise Security. After every
	// CallRatchetInterval, the initiator generates a fresh X25519 pair,
	// sends the pub via the chat Ratchet (MsgTypeCallRatchetPub), and mixes
	// DH(newPriv, peerPub) into the voice/video keys via HKDF. A single-
	// snapshot memory leak at time T can't decrypt frames from after the
	// next ratchet (attacker lacks the post-leak ephemerals).
	ratchetPriv    *[32]byte
	ratchetPeerPub *[32]byte
	ratchetMu      sync.Mutex

	// -------------- Video (ASCII) layer — optional during call ------------
	// Separate directional keys derived from the same call shared secret,
	// with a different HKDF info string so voice and video keys never
	// overlap.
	videoSendKey [32]byte
	videoRecvKey [32]byte
	videoSendGen uint64
	videoRecvGen uint64
	videoSendCtr uint64
	videoRecvCtr uint64
	// Our outgoing ASCII video stream (nil when not sending).
	videoStream network.Stream
	videoSource VideoSource
	videoStopCh chan struct{}
	videoWG     sync.WaitGroup

	// CallKind distinguishes voice-only (.call) from video (.vidcall) so the
	// receiver UI can show the right prompt and auto-enable video on accept.
	// Values: "voice" or "video".
	CallKind string

	// decisionCh is used by the CALLEE: the accept/decline goroutine (driven
	// by user input) signals the handshake goroutine through this channel.
	// true=accept, false=decline. Nil until an offer has been received.
	decisionCh chan bool

	// Call start time for logging.
	StartedAt time.Time
}

// -----------------------------------------------------------------------------
// Key derivation
// -----------------------------------------------------------------------------

// deriveCallKeys produces (sendKey, recvKey) for a call given the local
// peer ID, the remote peer ID and the X25519 shared secret. The direction
// labels are canonical across both sides: whichever peerID compares smaller
// in byte order is "A", the other is "B". Both sides then agree on
// keyAtoB and keyBtoA; each takes the one matching their role.
func deriveCallKeys(shared [32]byte, localID, remoteID peer.ID) (sendKey, recvKey [32]byte) {
	localBytes := []byte(localID)
	remoteBytes := []byte(remoteID)

	var keyAtoB, keyBtoA [32]byte
	var aID, bID []byte
	if bytes.Compare(localBytes, remoteBytes) < 0 {
		aID, bID = localBytes, remoteBytes
	} else {
		aID, bID = remoteBytes, localBytes
	}

	// info = "F2F-Call-v1|<aID>|<bID>|<direction>"
	buildInfo := func(dir string) []byte {
		buf := new(bytes.Buffer)
		buf.WriteString("F2F-Call-v1|")
		buf.Write(aID)
		buf.WriteByte('|')
		buf.Write(bID)
		buf.WriteByte('|')
		buf.WriteString(dir)
		return buf.Bytes()
	}

	deriveOne := func(info []byte) [32]byte {
		r := hkdf.New(sha256.New, shared[:], []byte("F2F-Call-Salt-v1"), info)
		var k [32]byte
		io.ReadFull(r, k[:])
		return k
	}

	keyAtoB = deriveOne(buildInfo("a2b"))
	keyBtoA = deriveOne(buildInfo("b2a"))

	if bytes.Compare(localBytes, remoteBytes) < 0 {
		return keyAtoB, keyBtoA
	}
	return keyBtoA, keyAtoB
}

// deriveVideoKeys follows the same scheme as deriveCallKeys but with a
// different HKDF context string so the resulting keys are cryptographically
// independent of the voice-call keys. This keeps the voice and video
// channels safe to use in parallel with the same 24-byte counter-only nonce
// scheme.
func deriveVideoKeys(shared [32]byte, localID, remoteID peer.ID) (sendKey, recvKey [32]byte) {
	localBytes := []byte(localID)
	remoteBytes := []byte(remoteID)

	var keyAtoB, keyBtoA [32]byte
	var aID, bID []byte
	if bytes.Compare(localBytes, remoteBytes) < 0 {
		aID, bID = localBytes, remoteBytes
	} else {
		aID, bID = remoteBytes, localBytes
	}

	buildInfo := func(dir string) []byte {
		buf := new(bytes.Buffer)
		buf.WriteString("F2F-Video-v1|")
		buf.Write(aID)
		buf.WriteByte('|')
		buf.Write(bID)
		buf.WriteByte('|')
		buf.WriteString(dir)
		return buf.Bytes()
	}

	deriveOne := func(info []byte) [32]byte {
		r := hkdf.New(sha256.New, shared[:], []byte("F2F-Video-Salt-v1"), info)
		var k [32]byte
		io.ReadFull(r, k[:])
		return k
	}

	keyAtoB = deriveOne(buildInfo("a2b"))
	keyBtoA = deriveOne(buildInfo("b2a"))

	if bytes.Compare(localBytes, remoteBytes) < 0 {
		return keyAtoB, keyBtoA
	}
	return keyBtoA, keyAtoB
}

// makeCallNonce builds a 24-byte XChaCha20 nonce from an 8-byte counter.
// The remaining 16 bytes are zero — safe because the key is direction-specific
// and the counter is unique per direction.
func makeCallNonce(ctr uint64) [24]byte {
	var n [24]byte
	binary.BigEndian.PutUint64(n[0:8], ctr)
	return n
}

// applyCallDHRatchet mixes a freshly-computed shared DH secret into all
// four live call keys (voice send/recv + video send/recv) via HKDF, giving
// Post-Compromise Security: a memory snapshot from before this ratchet
// event can't derive the new keys because `shared` depends on an ephemeral
// priv that wasn't in memory at that time.
//
// The per-direction info strings come from the same canonical peer-ID
// ordering used at initial key derivation, so both sides compute identical
// new keys without exchanging anything beyond the public DH half.
//
// Must be called with call.ratchetMu held.
func applyCallDHRatchet(call *CallSession, shared [32]byte, localID, remoteID peer.ID) {
	aIsLocal := bytes.Compare([]byte(localID), []byte(remoteID)) < 0

	buildInfo := func(label, dir string) []byte {
		var aID, bID []byte
		if aIsLocal {
			aID, bID = []byte(localID), []byte(remoteID)
		} else {
			aID, bID = []byte(remoteID), []byte(localID)
		}
		var buf bytes.Buffer
		buf.WriteString(label)
		buf.WriteByte('|')
		buf.Write(aID)
		buf.WriteByte('|')
		buf.Write(bID)
		buf.WriteByte('|')
		buf.WriteString(dir)
		return buf.Bytes()
	}

	mix := func(oldKey [32]byte, info []byte) [32]byte {
		// IKM = shared DH output, salt = old key. HKDF yields a new key
		// that's a function of BOTH the shared secret (fresh for PCS) and
		// the chain's history (preserves continuity).
		r := hkdf.New(sha256.New, shared[:], oldKey[:], info)
		var k [32]byte
		_, _ = io.ReadFull(r, k[:])
		return k
	}

	// Determine which old key corresponds to which direction, then
	// re-derive both, then assign back.
	var oldA2B_voice, oldB2A_voice, oldA2B_video, oldB2A_video [32]byte
	if aIsLocal {
		oldA2B_voice = call.sendKey
		oldB2A_voice = call.recvKey
		oldA2B_video = call.videoSendKey
		oldB2A_video = call.videoRecvKey
	} else {
		oldA2B_voice = call.recvKey
		oldB2A_voice = call.sendKey
		oldA2B_video = call.videoRecvKey
		oldB2A_video = call.videoSendKey
	}

	newA2B_voice := mix(oldA2B_voice, buildInfo("F2F-Call-DHRatchet-v1", "a2b"))
	newB2A_voice := mix(oldB2A_voice, buildInfo("F2F-Call-DHRatchet-v1", "b2a"))
	newA2B_video := mix(oldA2B_video, buildInfo("F2F-Video-DHRatchet-v1", "a2b"))
	newB2A_video := mix(oldB2A_video, buildInfo("F2F-Video-DHRatchet-v1", "b2a"))

	// Zero the old key bytes before losing the references.
	zeroKey := func(k *[32]byte) {
		for i := range k {
			k[i] = 0
		}
	}
	zeroKey(&call.sendKey)
	zeroKey(&call.recvKey)
	zeroKey(&call.videoSendKey)
	zeroKey(&call.videoRecvKey)

	if aIsLocal {
		call.sendKey = newA2B_voice
		call.recvKey = newB2A_voice
		call.videoSendKey = newA2B_video
		call.videoRecvKey = newB2A_video
	} else {
		call.sendKey = newB2A_voice
		call.recvKey = newA2B_voice
		call.videoSendKey = newB2A_video
		call.videoRecvKey = newA2B_video
	}

	// Reset the short-rotation (FS) generation counters — the new keys
	// start a fresh FS chain rooted in freshly-ratcheted material.
	call.sendGen = 0
	call.recvGen = 0
	call.videoSendGen = 0
	call.videoRecvGen = 0
}

// advanceCallKey derives the next-generation key from the current one via a
// one-way HKDF step. After rotation the caller zeroes the old key; since the
// KDF is one-way, an attacker who leaks the new key cannot recover past
// keys (forward secrecy within the call).
func advanceCallKey(current [32]byte) [32]byte {
	r := hkdf.New(sha256.New, current[:], nil, []byte("F2F-Call-KeyRotate-v1"))
	var next [32]byte
	_, _ = io.ReadFull(r, next[:])
	return next
}

// keyForCounter returns the key to use for a given frame counter, advancing
// `curKey`/`curGen` forward through HKDF chain as needed. The old key memory
// is zeroed before being replaced — best-effort protection for heap snapshots.
func keyForCounter(curKey *[32]byte, curGen *uint64, ctr uint64) [32]byte {
	targetGen := ctr / CallKeyRotateInterval
	for *curGen < targetGen {
		next := advanceCallKey(*curKey)
		// Zero the old key material before losing the reference.
		for i := range curKey {
			curKey[i] = 0
		}
		*curKey = next
		*curGen++
	}
	return *curKey
}

// -----------------------------------------------------------------------------
// Call frame format on the audio stream
// -----------------------------------------------------------------------------
// [4 bytes BE length][8 bytes BE counter][ciphertext = Opus + Poly1305 tag]

func writeCallFrame(w io.Writer, ctr uint64, ciphertext []byte) error {
	header := make([]byte, 4+8)
	binary.BigEndian.PutUint32(header[0:4], uint32(8+len(ciphertext)))
	binary.BigEndian.PutUint64(header[4:12], ctr)
	if _, err := w.Write(header); err != nil {
		return err
	}
	_, err := w.Write(ciphertext)
	return err
}

func readCallFrame(r io.Reader) (ctr uint64, ciphertext []byte, err error) {
	header := make([]byte, 4)
	if _, err = io.ReadFull(r, header); err != nil {
		return 0, nil, err
	}
	totalLen := binary.BigEndian.Uint32(header)
	if totalLen < 8 || totalLen > 4096 {
		return 0, nil, fmt.Errorf("call frame size out of range: %d", totalLen)
	}
	body := make([]byte, totalLen)
	if _, err = io.ReadFull(r, body); err != nil {
		return 0, nil, err
	}
	ctr = binary.BigEndian.Uint64(body[0:8])
	ciphertext = body[8:]
	return ctr, ciphertext, nil
}

// -----------------------------------------------------------------------------
// Control plane — independent of chat ratchet. Signaling happens IN-BAND on
// the AudioProtocolID stream itself:
//
//   byte 0:   message type  (OfferVoice=0x10, OfferVideo=0x11,
//                             Accept=0x20, Decline=0x21)
//   bytes 1..32: ephemeral X25519 pubkey (for Offer / Accept)
//
// After the handshake frames, the same stream carries encrypted audio frames
// via readCallFrame / writeCallFrame. A .call or .vidcall works without any
// prior .connect — the caller just dials the peer directly (via DHT lookup
// if not connected yet) and opens the call protocol stream.
// -----------------------------------------------------------------------------

const (
	sigOfferVoice byte = 0x10
	sigOfferVideo byte = 0x11
	sigAccept     byte = 0x20
	sigDecline    byte = 0x21
)

// InitiateCall opens a dedicated call stream to the peer and sends an Offer.
// `kind` is "voice" or "video". Spawns a goroutine that waits for the peer's
// Accept/Decline response and transitions state accordingly.
func (n *Node) InitiateCall(nickname string) error {
	return n.initiateCallKind(nickname, "voice")
}

// InitiateVideoCall is the same as InitiateCall but flags the offer as video.
func (n *Node) InitiateVideoCall(nickname string) error {
	return n.initiateCallKind(nickname, "video")
}

func (n *Node) initiateCallKind(nickname, kind string) error {
	c := n.getContactByNick(nickname)
	if c == nil {
		return errors.New("контакт не найден")
	}

	c.mu.Lock()
	if c.Call != nil && c.Call.State != CallIdle {
		c.mu.Unlock()
		return errors.New("звонок уже идёт")
	}
	priv, pub, err := generateEphemeralKeys()
	if err != nil {
		c.mu.Unlock()
		return fmt.Errorf("eph keys: %w", err)
	}
	c.Call = &CallSession{
		State:       CallOutgoing,
		localPriv:   priv,
		localPub:    pub,
		isInitiator: true,
		stopCh:      make(chan struct{}),
		StartedAt:   time.Now(),
		CallKind:    kind,
	}
	pid := c.PeerID
	c.mu.Unlock()

	// Ensure we can actually reach the peer. If not connected, do a DHT
	// lookup + libp2p Connect before opening the call stream.
	if err := n.ensurePeerReachable(pid, nickname); err != nil {
		c.mu.Lock()
		c.Call = nil
		c.mu.Unlock()
		return err
	}

	// Open the dedicated call stream. Allow limited conns (relay) — the
	// default rejection blocks sub-protocols over circuit-v2, which is
	// the #1 cause of silent call failure on NAT-restricted peers.
	ctx, cancel := context.WithTimeout(n.ctx, NewStreamTimeout)
	ctx = network.WithAllowLimitedConn(ctx, "f2f-call")
	s, err := n.host.NewStream(ctx, pid, AudioProtocolID)
	cancel()
	if err != nil {
		c.mu.Lock()
		c.Call = nil
		c.mu.Unlock()
		return fmt.Errorf("открыть поток: %w", err)
	}

	// Send the Offer frame: [type, 32 bytes pub].
	offerType := sigOfferVoice
	if kind == "video" {
		offerType = sigOfferVideo
	}
	offerFrame := append([]byte{offerType}, pub[:]...)
	s.SetWriteDeadline(time.Now().Add(WriteTimeout))
	if _, err := s.Write(offerFrame); err != nil {
		s.Reset()
		c.mu.Lock()
		c.Call = nil
		c.mu.Unlock()
		return fmt.Errorf("отправить offer: %w", err)
	}
	s.SetWriteDeadline(time.Time{})

	c.mu.Lock()
	if c.Call != nil {
		c.Call.stream = s
	}
	c.mu.Unlock()

	n.notifyCallOutgoing(pid, nickname, kind)

	// Wait for Accept/Decline response in a goroutine. Timeout covers
	// "peer never picked up".
	go n.awaitCallResponse(c, s, nickname)
	return nil
}

// awaitCallResponse reads the callee's response frame from the call stream
// and either activates the call (Accept) or tears it down (Decline/timeout).
func (n *Node) awaitCallResponse(c *Contact, s network.Stream, nickname string) {
	s.SetReadDeadline(time.Now().Add(CallOfferTimeout))
	hdr := make([]byte, 1)
	if _, err := io.ReadFull(s, hdr); err != nil {
		// Timeout or peer closed.
		c.mu.Lock()
		stillRinging := c.Call != nil && c.Call.State == CallOutgoing
		c.mu.Unlock()
		if stillRinging {
			n.closeCall(c, "нет ответа")
		}
		return
	}

	switch hdr[0] {
	case sigDecline:
		c.mu.Lock()
		c.Call = nil
		c.mu.Unlock()
		s.Reset()
		n.Log(LogLevelWarning, "%s отклонил вызов", nickname)
		n.notifyCallEnded(c.PeerID, nickname, "отклонён", "0s")
		n.notifyContactUpdate()

	case sigAccept:
		pubBuf := make([]byte, 32)
		if _, err := io.ReadFull(s, pubBuf); err != nil {
			n.closeCall(c, "accept: "+err.Error())
			return
		}
		var remotePub [32]byte
		copy(remotePub[:], pubBuf)

		c.mu.Lock()
		if c.Call == nil || c.Call.State != CallOutgoing {
			c.mu.Unlock()
			s.Reset()
			return
		}
		shared, err := computeDH(c.Call.localPriv, &remotePub)
		if err != nil {
			c.mu.Unlock()
			n.closeCall(c, "DH: "+err.Error())
			return
		}
		c.Call.sendKey, c.Call.recvKey = deriveCallKeys(shared, n.host.ID(), c.PeerID)
		c.Call.videoSendKey, c.Call.videoRecvKey = deriveVideoKeys(shared, n.host.ID(), c.PeerID)
		c.Call.ratchetPriv = c.Call.localPriv
		var peerCopy [32]byte
		peerCopy = remotePub
		c.Call.ratchetPeerPub = &peerCopy
		// Stream deadline off — data phase is deadlined per-frame.
		s.SetReadDeadline(time.Time{})
		c.mu.Unlock()

		if err := n.beginCall(c); err != nil {
			n.closeCall(c, "старт: "+err.Error())
			return
		}

		// Auto-start video on CALLER side too for .vidcall — symmetric
		// to what handleAudioStream does on the callee. Relying on the
		// TUI poller was racy with slow handshakes (relay).
		c.mu.Lock()
		callKind := ""
		if c.Call != nil {
			callKind = c.Call.CallKind
		}
		nickname := c.Nickname
		c.mu.Unlock()
		if callKind == "video" {
			go func() {
				time.Sleep(300 * time.Millisecond)
				if err := n.StartVideoFrom(nickname, ""); err != nil {
					n.Log(LogLevelWarning, "Видео со своей стороны не запустилось: %v", err)
				}
			}()
		}

	default:
		n.closeCall(c, "непонятный ответ от пира")
	}
}

// AcceptCall signals the in-progress handshake goroutine to accept. Derives
// shared keys and writes an Accept frame back down the call stream.
func (n *Node) AcceptCall(nickname string) error {
	c := n.getContactByNick(nickname)
	if c == nil {
		return errors.New("контакт не найден")
	}
	c.mu.Lock()
	if c.Call == nil || c.Call.State != CallIncoming {
		c.mu.Unlock()
		return errors.New("нет входящего вызова")
	}
	if c.Call.decisionCh == nil {
		c.mu.Unlock()
		return errors.New("внутренняя ошибка: no decisionCh")
	}
	ch := c.Call.decisionCh
	c.mu.Unlock()

	select {
	case ch <- true:
		return nil
	default:
		return errors.New("декодер вызова не готов")
	}
}

// DeclineCall rejects an incoming call.
func (n *Node) DeclineCall(nickname string) error {
	c := n.getContactByNick(nickname)
	if c == nil {
		return errors.New("контакт не найден")
	}
	c.mu.Lock()
	if c.Call == nil || c.Call.State != CallIncoming {
		c.mu.Unlock()
		return errors.New("нет входящего вызова")
	}
	if c.Call.decisionCh == nil {
		c.Call = nil
		c.mu.Unlock()
		return nil
	}
	ch := c.Call.decisionCh
	c.mu.Unlock()

	select {
	case ch <- false:
	default:
	}
	return nil
}

// EndCall terminates an active or outgoing call.
func (n *Node) EndCall(nickname string) error {
	c := n.getContactByNick(nickname)
	if c == nil {
		return errors.New("контакт не найден")
	}
	c.mu.Lock()
	if c.Call == nil {
		c.mu.Unlock()
		return errors.New("нет активного вызова")
	}
	c.mu.Unlock()
	n.closeCall(c, "вызов завершён")
	return nil
}

// ensurePeerReachable makes sure we have a live libp2p connection to the
// target. If not connected, does a DHT lookup and dial. Returns error
// only when we truly can't reach the peer within the standard timeout.
func (n *Node) ensurePeerReachable(pid peer.ID, nickname string) error {
	conn := n.host.Network().Connectedness(pid)
	if conn == network.Connected {
		return nil
	}
	if conn == network.Limited {
		// Relay-only reachability. Voice/video through a circuit-v2
		// relay is hard-capped at 128 KiB/direction → call dies in
		// ~25 s. We'd rather fail fast than ship a broken experience.
		// Give DCUtR a window to upgrade to direct first — most NATs
		// allow it.
		if n.waitForDirectUpgrade(pid, HolePunchWaitTimeout) {
			return nil
		}
		return errors.New("только relay — прямое соединение невозможно (симметричный NAT?). Для звонков нужно direct; попробуй VPN / IPv6 / свой relay")
	}
	// Peerstore addrs (from identify / earlier sessions) are kept; we
	// just ADD DHT results on top rather than replacing.
	ctx, cancel := context.WithTimeout(n.ctx, PeerLookupTimeout)
	info, err := n.dht.FindPeer(ctx, pid)
	cancel()
	if err == nil && len(info.Addrs) > 0 {
		n.host.Peerstore().AddAddrs(pid, info.Addrs, peerstore.AddressTTL)
	}

	// Dial with whatever we have (union of existing + DHT results).
	addrs := n.host.Peerstore().Addrs(pid)
	if len(addrs) == 0 {
		if err != nil {
			return fmt.Errorf("DHT: %v — и peerstore пуст", err)
		}
		return fmt.Errorf("%s не в сети (адресов нет)", nickname)
	}
	dctx, dcancel := context.WithTimeout(n.ctx, NewStreamTimeout)
	defer dcancel()
	if err := n.host.Connect(dctx, peer.AddrInfo{ID: pid, Addrs: addrs}); err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	return nil
}

// -----------------------------------------------------------------------------
// Audio stream — open/accept + capture/playback loops
// -----------------------------------------------------------------------------

// handleAudioStream is the libp2p handler for the call protocol.
// It reads the Offer frame, validates the caller, notifies the UI, and
// blocks until the user accepts or declines (or times out). On accept it
// derives shared keys, writes the Accept response, and starts audio loops.
//
// Callee side only — the initiator opens streams in initiateCallKind.
func (n *Node) handleAudioStream(s network.Stream) {
	remoteID := s.Conn().RemotePeer()
	c := n.getContactByID(remoteID)
	if c == nil {
		// Unknown peer — no contact card, we don't know who this is.
		s.Reset()
		return
	}

	// Refuse call streams that landed on a Limited (relay) connection.
	// We'd just die at the 128 KiB cap — fail fast with a clear decline
	// so the caller gets a proper error instead of a mid-call hangup.
	// Give DCUtR a brief window first in case it's about to upgrade.
	if s.Conn().Stat().Limited {
		if !n.waitForDirectUpgrade(remoteID, HolePunchWaitTimeout) {
			n.Log(LogLevelWarning,
				"[call] Отклоняю входящий вызов от %s — только relay, direct недоступен (128 KiB cap убил бы вызов)",
				c.Nickname)
			_, _ = s.Write([]byte{sigDecline})
			s.Reset()
			return
		}
	}

	// Reject if we're already in a call with this contact.
	c.mu.Lock()
	if c.Call != nil && c.Call.State != CallIdle {
		c.mu.Unlock()
		// Tell caller we're busy.
		_, _ = s.Write([]byte{sigDecline})
		s.Reset()
		return
	}
	c.mu.Unlock()

	// Read the Offer frame: 1 byte type + 32 bytes ephPub.
	s.SetReadDeadline(time.Now().Add(HandshakeTimeout))
	hdr := make([]byte, 33)
	if _, err := io.ReadFull(s, hdr); err != nil {
		s.Reset()
		return
	}
	kind := "voice"
	switch hdr[0] {
	case sigOfferVoice:
		kind = "voice"
	case sigOfferVideo:
		kind = "video"
	default:
		s.Reset()
		return
	}
	var remotePub [32]byte
	copy(remotePub[:], hdr[1:33])

	// Rate-limit: reject offers that arrive faster than CallOfferMinInterval
	// from the same peer. Protects against ringing spam.
	c.mu.Lock()
	if !c.LastCallOfferAt.IsZero() && time.Since(c.LastCallOfferAt) < CallOfferMinInterval {
		c.mu.Unlock()
		_, _ = s.Write([]byte{sigDecline})
		s.Reset()
		return
	}
	c.LastCallOfferAt = time.Now()

	// Build the incoming CallSession and user-decision channel.
	decisionCh := make(chan bool, 1)
	c.Call = &CallSession{
		State:               CallIncoming,
		DHRemotePubForSetup: &remotePub,
		stream:              s,
		stopCh:              make(chan struct{}),
		StartedAt:           time.Now(),
		CallKind:            kind,
		decisionCh:          decisionCh,
	}
	nick := c.Nickname
	c.mu.Unlock()

	// Tell the UI — single prompt, no chat dependency.
	n.notifyCallIncoming(c.PeerID, nick, kind)
	n.notifyContactUpdate()

	// Wait for user decision or timeout.
	var accepted bool
	select {
	case accepted = <-decisionCh:
	case <-time.After(CallOfferTimeout):
		c.mu.Lock()
		c.Call = nil
		c.mu.Unlock()
		_, _ = s.Write([]byte{sigDecline})
		s.Reset()
		n.notifyCallEnded(c.PeerID, nick, "таймаут", "0s")
		n.notifyContactUpdate()
		return
	case <-n.ctx.Done():
		s.Reset()
		return
	}

	if !accepted {
		c.mu.Lock()
		c.Call = nil
		c.mu.Unlock()
		_, _ = s.Write([]byte{sigDecline})
		s.Reset()
		n.Log(LogLevelInfo, "Вызов от %s отклонён", nick)
		n.notifyCallEnded(c.PeerID, nick, "отклонено", "0s")
		n.notifyContactUpdate()
		return
	}

	// Accepted — derive keys, respond, start loops.
	priv, pub, err := generateEphemeralKeys()
	if err != nil {
		n.closeCall(c, "eph keys: "+err.Error())
		return
	}
	shared, err := computeDH(priv, &remotePub)
	if err != nil {
		n.closeCall(c, "DH: "+err.Error())
		return
	}
	c.mu.Lock()
	if c.Call == nil {
		c.mu.Unlock()
		s.Reset()
		return
	}
	c.Call.localPriv = priv
	c.Call.localPub = pub
	c.Call.sendKey, c.Call.recvKey = deriveCallKeys(shared, n.host.ID(), c.PeerID)
	c.Call.videoSendKey, c.Call.videoRecvKey = deriveVideoKeys(shared, n.host.ID(), c.PeerID)
	c.Call.ratchetPriv = priv
	var peerCopy [32]byte
	peerCopy = remotePub
	c.Call.ratchetPeerPub = &peerCopy
	c.mu.Unlock()

	// Send Accept response: [sigAccept, 32 bytes ourPub].
	resp := append([]byte{sigAccept}, pub[:]...)
	s.SetWriteDeadline(time.Now().Add(WriteTimeout))
	if _, err := s.Write(resp); err != nil {
		n.closeCall(c, "отправить accept: "+err.Error())
		return
	}
	s.SetWriteDeadline(time.Time{})
	s.SetReadDeadline(time.Time{})

	if err := n.beginCall(c); err != nil {
		n.closeCall(c, "старт: "+err.Error())
		return
	}

	// Auto-start local video on the callee side when it's a video call.
	// Without this, video would be one-way (only caller → callee). The
	// user expectation for .vidcall is bidirectional video.
	if kind == "video" {
		go func() {
			// Small beat so CallActive has time to propagate to StartVideoFrom's
			// state check (it requires c.Call.State == CallActive).
			time.Sleep(300 * time.Millisecond)
			if err := n.StartVideoFrom(nick, ""); err != nil {
				n.Log(LogLevelWarning, "Видео со своей стороны не запустилось: %v", err)
			}
		}()
	}
}

// beginCall sets up Opus codecs, opens audio devices, and starts the
// capture/playback goroutines. By this point initiateCallKind /
// handleAudioStream have already guaranteed the underlying connection
// is DIRECT (relay-only was refused upstream), so we don't need to
// downshift bitrate here.
func (n *Node) beginCall(c *Contact) error {
	enc, err := newOpusEncoder(CallSampleRate, CallChannels)
	if err != nil {
		return fmt.Errorf("opus encoder: %w", err)
	}
	if err := enc.SetBitrate(CallOpusBitrate); err != nil {
		return fmt.Errorf("opus bitrate: %w", err)
	}
	// Tune encoder for best voice quality on mono wideband.
	_ = enc.SetComplexity(CallOpusComplexity)
	_ = enc.SetInbandFEC(true)
	_ = enc.SetPacketLossPercentage(CallOpusExpectedLossPct)
	_ = enc.SetSignalVoice()
	dec, err := newOpusDecoder(CallSampleRate, CallChannels)
	if err != nil {
		return fmt.Errorf("opus decoder: %w", err)
	}

	c.mu.Lock()
	if c.Call == nil {
		c.mu.Unlock()
		return errors.New("call gone")
	}
	c.Call.encoder = enc
	c.Call.decoder = dec
	c.Call.State = CallActive
	stream := c.Call.stream
	c.mu.Unlock()

	if stream == nil {
		return errors.New("no audio stream")
	}

	// Open capture + playback devices using the Node's selected audio settings.
	settings := LoadSettings()
	if err := n.openCallDevices(c, settings.AudioInputDeviceID, settings.AudioOutputDeviceID); err != nil {
		return fmt.Errorf("audio devices: %w", err)
	}

	n.wg.Add(2)
	go n.callReadLoop(c)
	go n.callCaptureLoop(c)

	// PCS DH ratchet was tied to chat Ratchet for its signaling channel.
	// With calls now independent of chat, the ratchet ticker would need
	// an in-band control frame — left as a follow-up. The per-frame HKDF
	// rotation (keyForCounter, every CallKeyRotateInterval frames) still
	// provides forward secrecy within a call.

	c.mu.Lock()
	kind := "voice"
	if c.Call != nil {
		kind = c.Call.CallKind
	}
	c.mu.Unlock()
	n.notifyCallActive(c.PeerID, c.Nickname, kind)
	return nil
}

func (n *Node) openCallDevices(c *Contact, inputID, outputID string) error {
	ctx, err := getAudioContext()
	if err != nil {
		return err
	}

	// --- Capture device: frames go into a channel consumed by callCaptureLoop.
	captureCfg := malgo.DefaultDeviceConfig(malgo.Capture)
	captureCfg.Capture.Format = malgo.FormatS16
	captureCfg.Capture.Channels = CallChannels
	captureCfg.SampleRate = CallSampleRate
	captureCfg.Alsa.NoMMap = 1
	if devID, err := deviceIDFromHex(inputID); err == nil && devID != nil {
		captureCfg.Capture.DeviceID = devID.Pointer()
	}

	var captureBuf []int16
	var captureMu sync.Mutex
	captureCallbacks := malgo.DeviceCallbacks{
		Data: func(_, input []byte, frameCount uint32) {
			// input is S16 little-endian interleaved
			samples := make([]int16, len(input)/2)
			for i := range samples {
				samples[i] = int16(input[i*2]) | int16(input[i*2+1])<<8
			}
			captureMu.Lock()
			captureBuf = append(captureBuf, samples...)
			captureMu.Unlock()
		},
	}
	captureDev, err := malgo.InitDevice(ctx.Context, captureCfg, captureCallbacks)
	if err != nil {
		return fmt.Errorf("init capture: %w", err)
	}

	// --- Playback device: pulls frames from the jitter buffer.
	playbackCfg := malgo.DefaultDeviceConfig(malgo.Playback)
	playbackCfg.Playback.Format = malgo.FormatS16
	playbackCfg.Playback.Channels = CallChannels
	playbackCfg.SampleRate = CallSampleRate
	if devID, err := deviceIDFromHex(outputID); err == nil && devID != nil {
		playbackCfg.Playback.DeviceID = devID.Pointer()
	}

	playbackCallbacks := malgo.DeviceCallbacks{
		Data: func(output, _ []byte, frameCount uint32) {
			c.mu.Lock()
			call := c.Call
			c.mu.Unlock()
			if call == nil {
				for i := range output {
					output[i] = 0
				}
				return
			}

			// Pull one frame from jitter buffer (or fall back).
			call.jitterMu.Lock()
			var frame []int16
			if len(call.jitter) > 0 {
				frame = call.jitter[0]
				call.jitter = call.jitter[1:]
				call.lastFrame = frame
			} else if call.lastFrame != nil {
				// Repeat last frame once (crude PLC) then silence.
				frame = call.lastFrame
				call.lastFrame = nil
			}
			call.jitterMu.Unlock()

			// Write samples to output buffer (interleaved S16 LE).
			n := int(frameCount) * int(CallChannels)
			if n > len(frame) {
				n = len(frame)
			}
			for i := 0; i < n; i++ {
				output[i*2] = byte(frame[i])
				output[i*2+1] = byte(frame[i] >> 8)
			}
			// Zero-fill the rest if frame was short.
			for i := n * 2; i < len(output); i++ {
				output[i] = 0
			}
		},
	}
	playbackDev, err := malgo.InitDevice(ctx.Context, playbackCfg, playbackCallbacks)
	if err != nil {
		captureDev.Uninit()
		return fmt.Errorf("init playback: %w", err)
	}

	if err := captureDev.Start(); err != nil {
		captureDev.Uninit()
		playbackDev.Uninit()
		return fmt.Errorf("start capture: %w", err)
	}
	if err := playbackDev.Start(); err != nil {
		captureDev.Stop()
		captureDev.Uninit()
		playbackDev.Uninit()
		return fmt.Errorf("start playback: %w", err)
	}

	// Attach the capture drain (pulled by callCaptureLoop).
	c.mu.Lock()
	c.Call.captureDevice = captureDev
	c.Call.playbackDevice = playbackDev
	c.Call.captureDrain = func() []int16 {
		captureMu.Lock()
		defer captureMu.Unlock()
		if len(captureBuf) < CallSamplesPerFrame {
			return nil
		}
		out := captureBuf[:CallSamplesPerFrame]
		captureBuf = captureBuf[CallSamplesPerFrame:]
		return out
	}
	c.mu.Unlock()

	return nil
}

// callCaptureLoop reads frames from the capture buffer, Opus-encodes them,
// encrypts with XChaCha20-Poly1305, and writes to the audio stream. The
// AEAD is rebuilt whenever the key rotates (every CallKeyRotateInterval
// frames) — `curGen` tracks which generation the current AEAD instance
// corresponds to.
func (n *Node) callCaptureLoop(c *Contact) {
	defer n.wg.Done()

	c.mu.Lock()
	call := c.Call
	c.mu.Unlock()
	if call == nil {
		return
	}

	aead, err := chacha20poly1305.NewX(call.sendKey[:])
	if err != nil {
		n.closeCall(c, "aead init: "+err.Error())
		return
	}

	ticker := time.NewTicker(time.Duration(CallFrameMs) * time.Millisecond)
	defer ticker.Stop()

	encodedBuf := make([]byte, 4000)
	for {
		select {
		case <-call.stopCh:
			return
		case <-n.ctx.Done():
			return
		case <-ticker.C:
		}

		c.mu.Lock()
		drain := call.captureDrain
		stream := call.stream
		c.mu.Unlock()
		if drain == nil || stream == nil {
			continue
		}

		pcm := drain()
		if pcm == nil {
			continue
		}

		nEnc, err := call.encoder.Encode(pcm, encodedBuf)
		if err != nil {
			continue
		}

		ctr := atomic.AddUint64(&call.sendCtr, 1)

		// Advance the send-side key if we've crossed a rotation boundary.
		targetGen := ctr / CallKeyRotateInterval
		if targetGen > call.sendGen {
			keyForCounter(&call.sendKey, &call.sendGen, ctr)
			newAead, aerr := chacha20poly1305.NewX(call.sendKey[:])
			if aerr != nil {
				n.closeCall(c, "rotate aead: "+aerr.Error())
				return
			}
			aead = newAead
		}

		nonce := makeCallNonce(ctr)
		ct := aead.Seal(nil, nonce[:], encodedBuf[:nEnc], nil)

		c.writeMu.Lock()
		stream.SetWriteDeadline(time.Now().Add(WriteTimeout))
		err = writeCallFrame(stream, ctr, ct)
		c.writeMu.Unlock()
		if err != nil {
			return
		}
	}
}

// callReadLoop reads encrypted frames from the audio stream, decrypts them,
// Opus-decodes, and pushes PCM frames into the jitter buffer.
func (n *Node) callReadLoop(c *Contact) {
	defer n.wg.Done()

	c.mu.Lock()
	call := c.Call
	c.mu.Unlock()
	if call == nil {
		return
	}

	aead, err := chacha20poly1305.NewX(call.recvKey[:])
	if err != nil {
		n.closeCall(c, "aead init: "+err.Error())
		return
	}

	pcmFrame := make([]int16, CallSamplesPerFrame)
	for {
		c.mu.Lock()
		stream := call.stream
		c.mu.Unlock()
		if stream == nil {
			return
		}
		stream.SetReadDeadline(time.Now().Add(StreamReadTimeout))
		ctr, ct, err := readCallFrame(stream)
		if err != nil {
			// Peer hung up / network broke. Log the concrete error so
			// we can tell relay bandwidth limit from a normal hangup.
			reason := classifyCallEndReason(err)
			n.Log(LogLevelInfo, "[call] завершение аудио-стрима: %s (%v)", reason, err)
			n.closeCall(c, reason)
			return
		}
		// Replay / reorder guard: reject strictly old counters.
		// Out-of-order within the last 32 frames is silently dropped
		// (could be added to jitter buffer with slot indexing, overkill).
		if ctr <= call.recvCtr {
			continue
		}
		call.recvCtr = ctr

		// Advance receive-side key if the counter crossed a rotation
		// boundary. Sender and receiver stay in lock-step because both
		// drive `gen` off the same global counter.
		targetGen := ctr / CallKeyRotateInterval
		if targetGen > call.recvGen {
			keyForCounter(&call.recvKey, &call.recvGen, ctr)
			newAead, aerr := chacha20poly1305.NewX(call.recvKey[:])
			if aerr != nil {
				n.closeCall(c, "rotate aead: "+aerr.Error())
				return
			}
			aead = newAead
		}

		nonce := makeCallNonce(ctr)
		plain, err := aead.Open(nil, nonce[:], ct, nil)
		if err != nil {
			continue // skip bad frame
		}
		nSamples, err := call.decoder.Decode(plain, pcmFrame)
		if err != nil || nSamples == 0 {
			continue
		}
		frameCopy := make([]int16, nSamples)
		copy(frameCopy, pcmFrame[:nSamples])

		call.jitterMu.Lock()
		call.jitter = append(call.jitter, frameCopy)
		// Cap the buffer to prevent unbounded growth if playback stalls.
		if len(call.jitter) > CallJitterFrames*8 {
			call.jitter = call.jitter[len(call.jitter)-CallJitterFrames*4:]
		}
		call.jitterMu.Unlock()
	}
}

// closeCall tears down devices, closes the audio stream, clears state.
func (n *Node) closeCall(c *Contact, reason string) {
	c.mu.Lock()
	call := c.Call
	c.Call = nil
	nick := c.Nickname
	c.mu.Unlock()
	if call == nil {
		return
	}

	call.once.Do(func() { close(call.stopCh) })

	// Tear down video first so its capture loop can exit cleanly.
	if call.videoStopCh != nil {
		select {
		case <-call.videoStopCh:
		default:
			close(call.videoStopCh)
		}
	}
	if call.videoStream != nil {
		call.videoStream.Close()
	}
	if call.videoSource != nil {
		_ = call.videoSource.Close()
	}
	call.videoWG.Wait()

	if call.captureDevice != nil {
		_ = call.captureDevice.Stop()
		call.captureDevice.Uninit()
	}
	if call.playbackDevice != nil {
		_ = call.playbackDevice.Stop()
		call.playbackDevice.Uninit()
	}
	if call.stream != nil {
		call.stream.Close()
	}
	// Explicitly free Opus state; finalizers are only a safety net.
	if call.encoder != nil {
		call.encoder.Close()
	}
	if call.decoder != nil {
		call.decoder.Close()
	}

	duration := time.Since(call.StartedAt).Round(time.Second)
	n.notifyCallEnded(c.PeerID, nick, reason, duration.String())
	n.notifyContactUpdate()
}

// -----------------------------------------------------------------------------
// Helper: curve25519 import guard (keeps compiler happy if we refactor)
// -----------------------------------------------------------------------------
var _ = curve25519.PointSize
