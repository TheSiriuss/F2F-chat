package f2f

import (
	"context"
	"crypto/rand"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
)

// realPeer is like testPeer but with a REAL libp2p host listening on
// 127.0.0.1 via TCP. No mocknet, no DHT — just direct addr exchange.
// This verifies that the code actually works with real transport.

type realPeer struct {
	node     *Node
	naclPub  [32]byte
	listener *recListener
}

// asTestPeer lets us reuse existing contact() / getState() helpers.
func (r *realPeer) asTestPeer() *testPeer {
	return &testPeer{node: r.node, naclPub: r.naclPub, listener: r.listener}
}

func newRealPeer(t *testing.T, nick string) *realPeer {
	t.Helper()
	h, err := libp2p.New(
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
	)
	if err != nil {
		t.Fatal(err)
	}

	var naclPub [32]byte
	if _, err := io.ReadFull(rand.Reader, naclPub[:]); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	list := &recListener{}
	node := &Node{
		host:         h,
		nickname:     nick,
		naclPublic:   naclPub,
		contacts:     make(map[peer.ID]*Contact),
		nickMap:      make(map[string]peer.ID),
		ctx:          ctx,
		cancel:       cancel,
		presenceChan: make(chan peer.ID, 100),
		listener:     list,
	}
	h.SetStreamHandler(ProtocolID, node.handleStream)
	h.SetStreamHandler(AudioProtocolID, node.handleAudioStream)

	t.Cleanup(func() {
		cancel()
		_ = h.Close()
	})
	return &realPeer{node: node, naclPub: naclPub, listener: list}
}

func realMutualAdd(me, other *realPeer, nick string) {
	c := &Contact{
		Nickname:   nick,
		PeerID:     other.node.host.ID(),
		PublicKey:  other.naclPub,
		SeenNonces: map[int64]time.Time{},
		State:      StateIdle,
		Presence:   PresenceUnknown,
	}
	me.node.mu.Lock()
	me.node.contacts[c.PeerID] = c
	me.node.nickMap[nick] = c.PeerID
	me.node.mu.Unlock()
	me.node.host.Peerstore().AddAddrs(
		other.node.host.ID(),
		other.node.host.Addrs(),
		peerstore.PermanentAddrTTL,
	)
}

func connectLibp2p(t *testing.T, a, b *realPeer) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.node.host.Connect(ctx, peer.AddrInfo{
		ID:    b.node.host.ID(),
		Addrs: b.node.host.Addrs(),
	}); err != nil {
		t.Fatalf("libp2p connect a→b: %v", err)
	}
}

func TestReal_InitConnect_Handshake_ActiveChat(t *testing.T) {
	chdirTemp(t)
	alice := newRealPeer(t, "alice")
	bob := newRealPeer(t, "bob")

	realMutualAdd(alice, bob, "bob")
	realMutualAdd(bob, alice, "alice")

	// Pre-connect at libp2p level so InitConnect doesn't block on DHT
	// (we don't run DHT in this test — the contact addrs are already in
	// the peerstore, so NewStream should succeed immediately).
	connectLibp2p(t, alice, bob)

	// Alice initiates chat (like `.connect bob`).
	go alice.node.InitConnect("bob")

	// Bob should see an incoming request.
	waitFor(t, "bob sees pending incoming", 10*time.Second, func() bool {
		c := contact(bob.asTestPeer(), alice.node.host.ID())
		if c == nil {
			return false
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.State == StatePendingIncoming
	})

	// Bob accepts.
	bob.node.HandleDecision("alice", true)

	// Both must end up in StateActive.
	waitFor(t, "alice active", 10*time.Second, func() bool {
		return getState(alice.asTestPeer(), bob.node.host.ID()) == StateActive
	})
	waitFor(t, "bob active", 10*time.Second, func() bool {
		return getState(bob.asTestPeer(), alice.node.host.ID()) == StateActive
	})
}

func TestReal_NewStream_DoesntTimeout(t *testing.T) {
	// Isolated test: just verify that host.NewStream works between two
	// real libp2p hosts when both have registered the protocol handler.
	chdirTemp(t)
	alice := newRealPeer(t, "alice")
	bob := newRealPeer(t, "bob")
	realMutualAdd(alice, bob, "bob")
	realMutualAdd(bob, alice, "alice")
	connectLibp2p(t, alice, bob)

	var ok int32
	bob.node.host.SetStreamHandler("/test/ping/1.0", func(s network.Stream) {
		atomic.StoreInt32(&ok, 1)
		s.Close()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := alice.node.host.NewStream(ctx, bob.node.host.ID(), "/test/ping/1.0")
	if err != nil {
		t.Fatalf("NewStream failed: %v", err)
	}
	s.Close()
	waitFor(t, "handler fired", 2*time.Second, func() bool {
		return atomic.LoadInt32(&ok) == 1
	})
}
