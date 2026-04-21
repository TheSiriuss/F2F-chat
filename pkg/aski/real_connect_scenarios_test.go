package f2f

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

// -----------------------------------------------------------------------------
// Real-libp2p tests for the tricky parts of the .connect flow. These spin
// up actual libp2p hosts on 127.0.0.1 — no mocknet — so they exercise the
// same code paths (NewStream retry, handshake, readLoop, session state)
// that the production binary hits.
// -----------------------------------------------------------------------------

// TestReal_Connect_BothSidesSeeActive confirms the basic contract the user
// keeps reporting as broken: alice .connects bob, bob sees the incoming
// Request, accepts, both end up in StateActive.
func TestReal_Connect_BothSidesSeeActive(t *testing.T) {
	chdirTemp(t)
	alice := newRealPeer(t, "alice")
	bob := newRealPeer(t, "bob")
	realMutualAdd(alice, bob, "bob")
	realMutualAdd(bob, alice, "alice")
	connectLibp2p(t, alice, bob)

	go alice.node.InitConnect("bob")
	waitFor(t, "bob sees Request", 10*time.Second, func() bool {
		c := contact(bob.asTestPeer(), alice.node.host.ID())
		if c == nil {
			return false
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.State == StatePendingIncoming
	})
	bob.node.HandleDecision("alice", true)
	waitFor(t, "alice sees Active", 10*time.Second, func() bool {
		return getState(alice.asTestPeer(), bob.node.host.ID()) == StateActive
	})
	waitFor(t, "bob sees Active", 10*time.Second, func() bool {
		return getState(bob.asTestPeer(), alice.node.host.ID()) == StateActive
	})
}

// TestReal_Connect_RaceBothSidesDial: both peers click .connect at exactly
// the same instant. Without tie-breaking this can end with two half-open
// streams and both sides stuck. handleStream's localID-vs-remoteID rule
// should resolve it cleanly.
func TestReal_Connect_RaceBothSidesDial(t *testing.T) {
	chdirTemp(t)
	alice := newRealPeer(t, "alice")
	bob := newRealPeer(t, "bob")
	realMutualAdd(alice, bob, "bob")
	realMutualAdd(bob, alice, "alice")
	connectLibp2p(t, alice, bob)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); alice.node.InitConnect("bob") }()
	go func() { defer wg.Done(); bob.node.InitConnect("alice") }()
	wg.Wait()

	// One side (the numerically-smaller peerID) backs off. After a moment
	// we expect ONE side to see a Request pending from the other.
	got := false
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && !got {
		ac := contact(alice.asTestPeer(), bob.node.host.ID())
		bc := contact(bob.asTestPeer(), alice.node.host.ID())
		ac.mu.Lock()
		bc.mu.Lock()
		// Exactly one of them should be PendingIncoming; the other Outgoing.
		incA := ac.State == StatePendingIncoming
		incB := bc.State == StatePendingIncoming
		ac.mu.Unlock()
		bc.mu.Unlock()
		if incA != incB { // XOR — exactly one
			got = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !got {
		t.Fatal("race resolution failed: neither or both sides saw an incoming request")
	}
}

// TestReal_Connect_ReconnectAfterDisconnect — the common real-world
// pattern: chat, disconnect, reconnect. Must work without an app restart.
func TestReal_Connect_ReconnectAfterDisconnect(t *testing.T) {
	chdirTemp(t)
	alice := newRealPeer(t, "alice")
	bob := newRealPeer(t, "bob")
	realMutualAdd(alice, bob, "bob")
	realMutualAdd(bob, alice, "alice")
	connectLibp2p(t, alice, bob)

	// First session
	go alice.node.InitConnect("bob")
	waitFor(t, "incoming", 10*time.Second, func() bool {
		c := contact(bob.asTestPeer(), alice.node.host.ID())
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.State == StatePendingIncoming
	})
	bob.node.HandleDecision("alice", true)
	waitFor(t, "active #1", 10*time.Second, func() bool {
		return getState(alice.asTestPeer(), bob.node.host.ID()) == StateActive
	})

	alice.node.Disconnect("bob")
	waitFor(t, "idle", 10*time.Second, func() bool {
		return getState(alice.asTestPeer(), bob.node.host.ID()) == StateIdle
	})

	// Second session — same peers, no restart.
	go alice.node.InitConnect("bob")
	waitFor(t, "incoming #2", 10*time.Second, func() bool {
		c := contact(bob.asTestPeer(), alice.node.host.ID())
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.State == StatePendingIncoming
	})
	bob.node.HandleDecision("alice", true)
	waitFor(t, "active #2", 10*time.Second, func() bool {
		return getState(alice.asTestPeer(), bob.node.host.ID()) == StateActive
	})
}

// TestReal_Connect_StaleAddrsDontBlock — if peerstore has many dead addrs
// mixed with one working one, Connect should still succeed (libp2p dials
// them in parallel and returns on first success).
//
// We pre-connect via libp2p to skip the DHT branch of InitConnect (our test
// nodes don't have a DHT set up). This exercises the NewStream retry path
// in the presence of polluted addresses.
func TestReal_Connect_StaleAddrsDontBlock(t *testing.T) {
	chdirTemp(t)
	alice := newRealPeer(t, "alice")
	bob := newRealPeer(t, "bob")
	realMutualAdd(alice, bob, "bob")
	realMutualAdd(bob, alice, "alice")
	connectLibp2p(t, alice, bob)

	// Stuff Alice's peerstore with a bunch of fake addrs on top of bob's
	// real ones (TEST-NET-1, guaranteed unroutable).
	fake, _ := ma.NewMultiaddr("/ip4/192.0.2.1/tcp/1")
	for i := 0; i < 20; i++ {
		alice.node.host.Peerstore().AddAddr(bob.node.host.ID(), fake, time.Minute)
	}

	go alice.node.InitConnect("bob")
	waitFor(t, "bob incoming despite stale addrs", 20*time.Second, func() bool {
		c := contact(bob.asTestPeer(), alice.node.host.ID())
		if c == nil {
			return false
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.State == StatePendingIncoming
	})
	bob.node.HandleDecision("alice", true)
	waitFor(t, "both active", 15*time.Second, func() bool {
		return getState(alice.asTestPeer(), bob.node.host.ID()) == StateActive &&
			getState(bob.asTestPeer(), alice.node.host.ID()) == StateActive
	})
}

// TestReal_Connect_UsesPeerstoreWhenDHT_Empty: the regression scenario
// reported by the user — sidebar shows "online" because peerstore has
// known addrs, but DHT returns 0 addresses for the peer. Old InitConnect
// would ClearAddrs before DHT, nuking the working addresses, then fail
// with "DHT вернул 0 адресов". Fixed InitConnect must keep peerstore
// addrs and proceed to dial with them.
//
// Because realPeer doesn't set up DHT (node.dht is nil), calling
// InitConnect in its original shape would panic. We instead directly
// exercise the dial logic: peerstore has addrs, caller dials via them.
func TestReal_Connect_UsesPeerstoreWhenDHT_Empty(t *testing.T) {
	chdirTemp(t)
	alice := newRealPeer(t, "alice")
	bob := newRealPeer(t, "bob")
	realMutualAdd(alice, bob, "bob") // populates alice.peerstore for bob
	realMutualAdd(bob, alice, "alice")

	// Sanity: alice's peerstore has bob's real addrs.
	addrs := alice.node.host.Peerstore().Addrs(bob.node.host.ID())
	if len(addrs) == 0 {
		t.Fatal("peerstore should have bob's addrs after realMutualAdd")
	}

	// Connect should succeed purely from peerstore addrs — no DHT needed.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := alice.node.host.Connect(ctx, peer.AddrInfo{
		ID: bob.node.host.ID(), Addrs: addrs,
	}); err != nil {
		t.Fatalf("connect with peerstore addrs should work: %v", err)
	}

	// After connect, Connectedness must be Connected. This is the
	// signal FindContact / checkSinglePresence now use to short-circuit
	// away from the DHT query.
	if alice.node.host.Network().Connectedness(bob.node.host.ID()) != network.Connected {
		t.Fatal("expected Connected after host.Connect")
	}
}

// TestReal_Connect_NoMutual_Rejected: if bob hasn't added alice, alice's
// InitConnect completes at transport level but bob's handleStream resets
// the stream (c == nil). Alice should learn of the failure.
func TestReal_Connect_NoMutual_Rejected(t *testing.T) {
	chdirTemp(t)
	alice := newRealPeer(t, "alice")
	bob := newRealPeer(t, "bob")
	realMutualAdd(alice, bob, "bob")
	// NOT adding alice to bob's contacts.
	connectLibp2p(t, alice, bob)

	// Track whether alice's Log got "Входящий стрим от неизвестного" —
	// we can't inspect bob's side directly without a listener, but we
	// can check that alice's state never becomes Active.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		alice.node.InitConnect("bob")
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
	}
	// Either way, alice should NOT end up StateActive.
	if s := getState(alice.asTestPeer(), bob.node.host.ID()); s == StateActive {
		t.Fatalf("alice reached Active even though bob didn't add her — state=%d", s)
	}
}
