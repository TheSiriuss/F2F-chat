package f2f

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peer"
)

// -----------------------------------------------------------------------------
// Real-libp2p tests for the per-contact address cache (KnownAddrs).
//
// These don't use mocknet — they spin up actual libp2p Hosts listening on
// 127.0.0.1/tcp/0 and drive them through the real InitConnect / readLoop
// code path. DHT is intentionally NOT set up (node.dht is nil) — if InitConnect
// falls through to the DHT branch, the test panics, which is how we assert
// that the cache path was taken.
// -----------------------------------------------------------------------------

// addContactWithKnownAddrs registers `other` as a contact of `me` with the
// given KnownAddrs, WITHOUT populating me's peerstore. The peerstore pre-fill
// normally happens in LoadContacts on startup; we skip it here so InitConnect
// has to actually walk the cache → peerstore → Connect path.
func addContactWithKnownAddrs(me, other *realPeer, asNick string, addrs []string) *Contact {
	c := &Contact{
		Nickname:   asNick,
		PeerID:     other.node.host.ID(),
		PublicKey:  other.naclPub,
		KnownAddrs: addrs,
		SeenNonces: map[int64]time.Time{},
		State:      StateIdle,
		Presence:   PresenceUnknown,
	}
	me.node.mu.Lock()
	me.node.contacts[c.PeerID] = c
	me.node.nickMap[asNick] = c.PeerID
	me.node.mu.Unlock()
	return c
}

func stringifyAddrs(p *realPeer) []string {
	var out []string
	for _, a := range p.node.host.Addrs() {
		out = append(out, a.String())
	}
	return out
}

// TestReal_KnownAddrs_SkipsDHT verifies that when a contact has KnownAddrs
// set but the peerstore is empty, .connect uses the cache path and succeeds
// without ever touching DHT.
func TestReal_KnownAddrs_SkipsDHT(t *testing.T) {
	t.Skip("address cache path removed — .connect always uses DHT now")
	chdirTemp(t)

	alice := newRealPeer(t, "alice")
	bob := newRealPeer(t, "bob")

	// Alice knows Bob's addrs in cache — peerstore is empty.
	addContactWithKnownAddrs(alice, bob, "bob", stringifyAddrs(bob))
	// Bob has alice mutually (with peerstore, since bob doesn't initiate).
	realMutualAdd(bob, alice, "alice")

	go alice.node.InitConnect("bob")

	waitFor(t, "bob sees incoming", 10*time.Second, func() bool {
		c := contact(bob.asTestPeer(), alice.node.host.ID())
		if c == nil {
			return false
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.State == StatePendingIncoming
	})

	bob.node.HandleDecision("alice", true)

	waitFor(t, "both active", 10*time.Second, func() bool {
		return getState(alice.asTestPeer(), bob.node.host.ID()) == StateActive &&
			getState(bob.asTestPeer(), alice.node.host.ID()) == StateActive
	})
}

// TestReal_AddrsCachedAfterHandshake verifies that the cache gets populated
// (or refreshed) after a successful session is established.
func TestReal_AddrsCachedAfterHandshake(t *testing.T) {
	t.Skip("rememberSuccessfulAddrs no longer called — cache disabled")
	chdirTemp(t)

	alice := newRealPeer(t, "alice")
	bob := newRealPeer(t, "bob")

	// Start with EMPTY cache — addrs only in peerstore (normal mutual-add).
	realMutualAdd(alice, bob, "bob")
	realMutualAdd(bob, alice, "alice")

	// Pre-connect so InitConnect skips the DHT/Connect phase.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := alice.node.host.Connect(ctx, peer.AddrInfo{
		ID: bob.node.host.ID(), Addrs: bob.node.host.Addrs(),
	}); err != nil {
		t.Fatal(err)
	}

	go alice.node.InitConnect("bob")
	waitFor(t, "bob pending", 10*time.Second, func() bool {
		c := contact(bob.asTestPeer(), alice.node.host.ID())
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.State == StatePendingIncoming
	})
	bob.node.HandleDecision("alice", true)
	waitFor(t, "alice active", 10*time.Second, func() bool {
		return getState(alice.asTestPeer(), bob.node.host.ID()) == StateActive
	})

	// rememberSuccessfulAddrs should have been called in readLoop — give it
	// a short beat to land.
	time.Sleep(100 * time.Millisecond)

	ac := contact(alice.asTestPeer(), bob.node.host.ID())
	ac.mu.Lock()
	n := len(ac.KnownAddrs)
	ac.mu.Unlock()
	if n == 0 {
		t.Fatalf("alice's cache for bob is still empty after successful handshake")
	}
}

// TestReal_ReconnectAfterIdle: establish session, disconnect, wait a while,
// reconnect using only the cache. Simulates the "10 minutes later" scenario
// in a CI-friendly ~5 seconds (skipped under -short to allow 30s in full mode).
func TestReal_ReconnectAfterIdle(t *testing.T) {
	t.Skip("reconnect uses DHT now — covered by TestReal_Connect_ReconnectAfterDisconnect")
	chdirTemp(t)

	idle := 3 * time.Second
	if !testing.Short() {
		idle = 15 * time.Second
	}

	alice := newRealPeer(t, "alice")
	bob := newRealPeer(t, "bob")

	// First connection — via peerstore + Connect pre-population.
	realMutualAdd(alice, bob, "bob")
	realMutualAdd(bob, alice, "alice")
	connectLibp2p(t, alice, bob)

	go alice.node.InitConnect("bob")
	waitFor(t, "bob pending #1", 10*time.Second, func() bool {
		c := contact(bob.asTestPeer(), alice.node.host.ID())
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.State == StatePendingIncoming
	})
	bob.node.HandleDecision("alice", true)
	waitFor(t, "alice active #1", 10*time.Second, func() bool {
		return getState(alice.asTestPeer(), bob.node.host.ID()) == StateActive
	})

	// Disconnect — tear the chat session down.
	alice.node.Disconnect("bob")
	waitFor(t, "alice idle", 10*time.Second, func() bool {
		return getState(alice.asTestPeer(), bob.node.host.ID()) == StateIdle
	})

	t.Logf("sleeping %s to simulate idle period", idle)
	time.Sleep(idle)

	// Reconnect — should use cached addrs.
	go alice.node.InitConnect("bob")
	waitFor(t, "bob pending #2", 10*time.Second, func() bool {
		c := contact(bob.asTestPeer(), alice.node.host.ID())
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.State == StatePendingIncoming
	})
	bob.node.HandleDecision("alice", true)
	waitFor(t, "alice active #2", 10*time.Second, func() bool {
		return getState(alice.asTestPeer(), bob.node.host.ID()) == StateActive
	})
}

// TestReal_SimulatedRestart_CacheLoadsFromDisk: save alice's state,
// fully shut her down (close host), spin up a NEW alice with the SAME
// libp2p identity, and verify .connect works from cache alone.
func TestReal_SimulatedRestart_CacheLoadsFromDisk(t *testing.T) {
	t.Skip("cache removed — restart goes through DHT")
	chdirTemp(t)

	alice := newRealPeer(t, "alice")
	bob := newRealPeer(t, "bob")

	realMutualAdd(alice, bob, "bob")
	realMutualAdd(bob, alice, "alice")
	connectLibp2p(t, alice, bob)

	// Round 1
	go alice.node.InitConnect("bob")
	waitFor(t, "bob pending", 10*time.Second, func() bool {
		c := contact(bob.asTestPeer(), alice.node.host.ID())
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.State == StatePendingIncoming
	})
	bob.node.HandleDecision("alice", true)
	waitFor(t, "active", 10*time.Second, func() bool {
		return getState(alice.asTestPeer(), bob.node.host.ID()) == StateActive
	})

	// Pull alice's cached addrs, snapshot her libp2p priv key, then
	// simulate a process restart by closing the old host and building a
	// new one with the same priv key.
	ac := contact(alice.asTestPeer(), bob.node.host.ID())
	ac.mu.Lock()
	snap := append([]string(nil), ac.KnownAddrs...)
	ac.mu.Unlock()
	if len(snap) == 0 {
		t.Fatal("alice's cache empty after handshake — cannot test restart")
	}

	alicePriv := alice.node.host.Peerstore().PrivKey(alice.node.host.ID())
	alice.node.cancel()
	_ = alice.node.host.Close()

	// Spin up NEW alice with the same identity.
	h, err := libp2p.New(
		libp2p.Identity(alicePriv),
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })

	ctx2, cancel2 := context.WithCancel(context.Background())
	t.Cleanup(cancel2)
	list2 := &recListener{}
	alice2 := &Node{
		host:         h,
		nickname:     "alice",
		naclPublic:   alice.naclPub,
		contacts:     make(map[peer.ID]*Contact),
		nickMap:      make(map[string]peer.ID),
		ctx:          ctx2,
		cancel:       cancel2,
		presenceChan: make(chan peer.ID, 100),
		listener:     list2,
	}
	h.SetStreamHandler(ProtocolID, alice2.handleStream)
	h.SetStreamHandler(AudioProtocolID, alice2.handleAudioStream)
	h.SetStreamHandler(VideoProtocolID, alice2.handleVideoStream)

	// Register bob with ONLY the cached addrs — no peerstore pre-fill,
	// no DHT, no explicit pre-connect. This is the "fresh restart" state.
	addContactWithKnownAddrs(&realPeer{node: alice2, naclPub: alice.naclPub, listener: list2}, bob, "bob", snap)

	// Bob still has alice in his contacts from setup. But bob needs to
	// recognise the NEW alice (same peerID, different host) — peerID is
	// derived from libp2p priv, so it's the same. Good.

	time.Sleep(300 * time.Millisecond) // let libp2p settle

	go alice2.InitConnect("bob")
	waitFor(t, "bob pending after restart", 15*time.Second, func() bool {
		c := contact(bob.asTestPeer(), alice2.host.ID())
		if c == nil {
			return false
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.State == StatePendingIncoming
	})
	bob.node.HandleDecision("alice", true)
	waitFor(t, "active after restart", 15*time.Second, func() bool {
		// Use alice2's local view via manual lookup.
		c := func() *Contact {
			alice2.mu.RLock()
			defer alice2.mu.RUnlock()
			return alice2.contacts[bob.node.host.ID()]
		}()
		if c == nil {
			return false
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.State == StateActive
	})
}
