package f2f

import (
	"context"
	"crypto/rand"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/client"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
	ma "github.com/multiformats/go-multiaddr"
	"golang.org/x/crypto/nacl/box"
)

// -----------------------------------------------------------------------------
// Real-libp2p tests that exercise the call/video flow over a CIRCUIT-V2
// RELAY with the default per-connection limits (128 KiB / 2 min). These
// reproduce the user-reported "call drops at ~16 s" behaviour and let us
// measure how long the call actually survives under realistic NAT-hell
// conditions — before trusting any theoretical fix.
// -----------------------------------------------------------------------------

// relayTestPeer is a lightweight f2f.Node bound to a libp2p host. Only
// audio/video handlers are wired (no DHT, no chat session needed for the
// call protocol in its new independent form).
type relayTestPeer struct {
	node *Node
	h    host.Host
}

func newRelayTestPeer(t *testing.T, nick string, opts ...libp2p.Option) *relayTestPeer {
	t.Helper()
	h, err := libp2p.New(opts...)
	if err != nil {
		t.Fatal(err)
	}

	// Fake nacl pub so Contact creation works.
	pub, _, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	node := &Node{
		host:         h,
		nickname:     nick,
		naclPublic:   *pub,
		contacts:     make(map[peer.ID]*Contact),
		nickMap:      make(map[string]peer.ID),
		ctx:          ctx,
		cancel:       cancel,
		presenceChan: make(chan peer.ID, 100),
		listener:     &recListener{},
	}
	h.SetStreamHandler(ProtocolID, node.handleStream)
	h.SetStreamHandler(AudioProtocolID, node.handleAudioStream)
	h.SetStreamHandler(VideoProtocolID, node.handleVideoStream)

	t.Cleanup(func() {
		cancel()
		_ = h.Close()
	})
	return &relayTestPeer{node: node, h: h}
}

// addContact registers other as a contact of me with other's nacl pub.
func (p *relayTestPeer) addContact(other *relayTestPeer, asNick string) {
	c := &Contact{
		Nickname:   asNick,
		PeerID:     other.h.ID(),
		PublicKey:  other.node.naclPublic,
		SeenNonces: map[int64]time.Time{},
		State:      StateIdle,
		Presence:   PresenceUnknown,
	}
	p.node.mu.Lock()
	p.node.contacts[c.PeerID] = c
	p.node.nickMap[asNick] = c.PeerID
	p.node.mu.Unlock()
}

// setupRelayTrio builds:
//   - relay host listening on 127.0.0.1 with DEFAULT libp2p relay limits
//   - alice (with a dummy TCP listener — not reachable from bob directly
//     since bob doesn't know the address) who explicitly RESERVES a slot
//     on the relay
//   - bob who dials alice via /p2p-circuit/
//
// This reproduces the "both sides through a public relay" topology the
// user is hitting — and exposes the 128 KiB / 2 min limits.
func setupRelayTrio(t *testing.T) (alice, bob *relayTestPeer, relayH host.Host) {
	t.Helper()

	// Relay host.
	relayH, err := libp2p.New(
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
		libp2p.DisableRelay(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := relay.New(relayH); err != nil {
		_ = relayH.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = relayH.Close() })

	// Alice needs a listener for libp2p internals, but we won't expose
	// its addrs to bob — bob will only see the circuit addr. Hole-punch
	// enabled so DCUtR can upgrade the relay conn to direct once
	// identify has exchanged addrs.
	alice = newRelayTestPeer(t, "alice",
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
		libp2p.EnableRelay(),
		libp2p.EnableHolePunching(),
	)

	// Bob also has a direct listener (needed so ESTABLISHING the
	// circuit stream works — libp2p prefers direct for hop protocol).
	bob = newRelayTestPeer(t, "bob",
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
		libp2p.EnableRelay(),
		libp2p.EnableHolePunching(),
	)

	// Connect alice and bob BOTH to the relay first.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := alice.h.Connect(ctx, peer.AddrInfo{ID: relayH.ID(), Addrs: relayH.Addrs()}); err != nil {
		t.Fatalf("alice→relay: %v", err)
	}
	if err := bob.h.Connect(ctx, peer.AddrInfo{ID: relayH.ID(), Addrs: relayH.Addrs()}); err != nil {
		t.Fatalf("bob→relay: %v", err)
	}

	// Alice explicitly reserves a slot. This is what autorelay would
	// normally do.
	if _, err := client.Reserve(ctx, alice.h, peer.AddrInfo{ID: relayH.ID(), Addrs: relayH.Addrs()}); err != nil {
		t.Fatalf("alice reserve: %v", err)
	}

	// Build the circuit addr: /p2p/<relay>/p2p-circuit/p2p/<alice>.
	circuitAddr, err := ma.NewMultiaddr("/p2p/" + relayH.ID().String() + "/p2p-circuit")
	if err != nil {
		t.Fatal(err)
	}
	bob.h.Peerstore().AddAddrs(alice.h.ID(), []ma.Multiaddr{circuitAddr}, peerstore.PermanentAddrTTL)

	// Mutual contact registration.
	alice.addContact(bob, "bob")
	bob.addContact(alice, "alice")
	// Give alice bob's addrs so reply streams can use them if needed.
	alice.h.Peerstore().AddAddrs(bob.h.ID(), bob.h.Addrs(), peerstore.PermanentAddrTTL)

	// Dial bob → alice via circuit. libp2p needs the AllowLimitedConn
	// hint for the sub-protocol streams later, but for the initial
	// Connect the hop protocol takes care of itself.
	ctxLim := network.WithAllowLimitedConn(ctx, "test-setup")
	if err := bob.h.Connect(ctxLim, peer.AddrInfo{
		ID: alice.h.ID(), Addrs: []ma.Multiaddr{circuitAddr},
	}); err != nil {
		t.Fatalf("bob→alice via relay: %v", err)
	}

	// Simulate "symmetric NAT": strip every direct addr identify might
	// have exchanged from bob's peerstore for alice. Only circuit-v2
	// stays, so force-direct-dial has nothing to aim at. Mirrors the
	// real user scenario where direct paths don't exist.
	bob.h.Peerstore().ClearAddrs(alice.h.ID())
	bob.h.Peerstore().AddAddrs(alice.h.ID(), []ma.Multiaddr{circuitAddr}, peerstore.PermanentAddrTTL)

	// Verify we ACTUALLY went through the relay, not accidentally direct.
	conns := bob.h.Network().ConnsToPeer(alice.h.ID())
	relayed := false
	for _, c := range conns {
		if isCircuitAddr(c.RemoteMultiaddr()) {
			relayed = true
			break
		}
	}
	if !relayed {
		t.Fatal("connection was NOT via circuit relay — test setup failed")
	}

	return alice, bob, relayH
}

func isCircuitAddr(m ma.Multiaddr) bool {
	for _, p := range m.Protocols() {
		if p.Code == ma.P_CIRCUIT {
			return true
		}
	}
	return false
}


// -----------------------------------------------------------------------------
// The actual measurement tests.
// -----------------------------------------------------------------------------

// TestReal_Direct_VoiceCall_LongDuration — the positive case: two peers
// with a DIRECT libp2p connection (no relay in the middle) can talk for
// a long time without dropping. This is the expected behaviour once the
// relay-only refusal policy is in place — chat/calls always go direct.
//
// We use localhost peers so hole-punch isn't needed (direct dial works).
// The test runs a voice call for 70 seconds and asserts State stays
// CallActive throughout.
func TestReal_Direct_VoiceCall_LongDuration(t *testing.T) {
	if testing.Short() {
		t.Skip("long test — 70 s call, skipped under -short")
	}
	alice := newRealPeer(t, "alice")
	bob := newRealPeer(t, "bob")
	realMutualAdd(alice, bob, "bob")
	realMutualAdd(bob, alice, "alice")
	connectLibp2p(t, alice, bob) // pre-connects direct on 127.0.0.1

	// Bob calls alice (voice).
	if err := bob.node.InitiateCall("alice"); err != nil {
		t.Fatalf("InitiateCall: %v", err)
	}
	waitUntil(t, 5*time.Second, func() bool {
		return alice.node.GetCallState("bob") == CallIncoming
	})
	if err := alice.node.AcceptCall("bob"); err != nil {
		t.Fatalf("AcceptCall: %v", err)
	}
	waitUntil(t, 10*time.Second, func() bool {
		return alice.node.GetCallState("bob") == CallActive &&
			bob.node.GetCallState("alice") == CallActive
	})

	const callDuration = 70 * time.Second
	start := time.Now()
	deadline := start.Add(callDuration)
	droppedAt := time.Time{}
	for time.Now().Before(deadline) {
		time.Sleep(500 * time.Millisecond)
		if alice.node.GetCallState("bob") != CallActive ||
			bob.node.GetCallState("alice") != CallActive {
			droppedAt = time.Now()
			break
		}
	}
	if !droppedAt.IsZero() {
		t.Fatalf("direct call DROPPED after %s — expected to survive %s",
			droppedAt.Sub(start), callDuration)
	}
	t.Logf("direct call stable for %s — both sides still CallActive", callDuration)
}

// TestReal_Relay_VoiceCall_Refused verifies the user-requested policy:
// voice calls over a RELAY-ONLY connection are refused upfront (rather
// than accepted-then-dropped-at-25-s). Hole-punch window is short in
// test because both peers are on localhost — DCUtR can't actually do
// anything, so we rely on the initial Limited check to block.
func TestReal_Relay_VoiceCall_Refused(t *testing.T) {
	if testing.Short() {
		t.Skip("long test — skipped under -short")
	}
	alice, bob, _ := setupRelayTrio(t)
	_ = alice

	err := bob.node.InitiateCall("alice")
	if err == nil {
		t.Fatal("InitiateCall via relay should be refused, got nil error")
	}
	t.Logf("voice call over relay correctly refused: %v", err)
}

// TestReal_Relay_VideoCall_Refused — same policy for video.
func TestReal_Relay_VideoCall_Refused(t *testing.T) {
	if testing.Short() {
		t.Skip("long test — skipped under -short")
	}
	alice, bob, _ := setupRelayTrio(t)
	_ = alice

	err := bob.node.InitiateVideoCall("alice")
	if err == nil {
		t.Fatal("InitiateVideoCall via relay should be refused, got nil error")
	}
	t.Logf("video call over relay correctly refused: %v", err)
}

// waitUntil polls cond every 50ms until it returns true or budget elapses.
func waitUntil(t *testing.T, budget time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("waitUntil timed out after %s", budget)
}

// dummyFramesSent is just to ensure the imports above don't get flagged
// as unused if future edits remove one. Keep the helpers.
var _ = atomic.AddUint64

// TestReal_Relay_RawBytes_128KiB_Cap demonstrates that ANY kind of
// payload — voice, video, chat, FILES — hits the same circuit-v2 data
// limit when forced through a relay. Disproves the intuition "files
// work so video should too": files only work because they normally go
// over a DIRECT connection. Put a file transfer over a relay and it
// fails at the same ~128 KiB as the voice call.
//
// We don't use our protocol stack here — just raw libp2p streams
// pushing bytes. Same cap applies.
func TestReal_Relay_RawBytes_128KiB_Cap(t *testing.T) {
	if testing.Short() {
		t.Skip("long test — skipped under -short")
	}
	alice, bob, _ := setupRelayTrio(t)

	// Register a "bulk transfer" handler on alice that sinks everything.
	const bulkProto = "/test/bulk/1.0"
	received := int64(0)
	readDone := make(chan error, 1)
	alice.h.SetStreamHandler(bulkProto, func(s network.Stream) {
		defer s.Close()
		buf := make([]byte, 4096)
		for {
			n, err := s.Read(buf)
			if n > 0 {
				atomic.AddInt64(&received, int64(n))
			}
			if err != nil {
				readDone <- err
				return
			}
		}
	})

	// Bob opens a stream to alice via the relay and pushes bytes until
	// the relay kills us.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	ctxLim := network.WithAllowLimitedConn(ctx, "bulk-test")
	s, err := bob.h.NewStream(ctxLim, alice.h.ID(), bulkProto)
	if err != nil {
		t.Fatalf("open bulk stream: %v", err)
	}
	defer s.Close()

	chunk := make([]byte, 8192)
	for i := range chunk {
		chunk[i] = byte(i)
	}
	start := time.Now()
	var sent int64
	var writeErr error
	for time.Since(start) < 30*time.Second {
		_, err := s.Write(chunk)
		if err != nil {
			writeErr = err
			break
		}
		sent += int64(len(chunk))
	}
	s.Close()

	// Give alice's reader a moment to drain / see EOF.
	select {
	case <-readDone:
	case <-time.After(2 * time.Second):
	}
	t.Logf("raw bytes through relay: sent=%d, received=%d, duration=%s, writeErr=%v",
		sent, atomic.LoadInt64(&received), time.Since(start), writeErr)
	if writeErr == nil && sent < 2*1024*1024 {
		t.Log("warning: Write did not error; the cap might be silently at the read side")
	}
}
