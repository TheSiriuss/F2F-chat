package f2f

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	mocknet "github.com/libp2p/go-libp2p/p2p/net/mock"
	"golang.org/x/crypto/nacl/box"
)

// ------------------------------------------------------------------
// Test listener: records everything
// ------------------------------------------------------------------

type recordedMsg struct {
	PeerID string
	Nick   string
	Text   string
	TS     time.Time
}

type recordedOffer struct {
	PeerID, Nick, Name string
	Size               int64
}

type recordedReceived struct {
	PeerID, Nick, Name, Path string
	Size                     int64
}

type recordedComplete struct {
	PeerID, Nick, Name, Message string
	Success                     bool
}

type recListener struct {
	mu          sync.Mutex
	messages    []recordedMsg
	offers      []recordedOffer
	received    []recordedReceived
	complete    []recordedComplete
	chatChanges []string
	logs        []string
	updates     int32
	progress    int32
}

func (r *recListener) OnMessage(pid, nick, text string, ts time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.messages = append(r.messages, recordedMsg{pid, nick, text, ts})
}
func (r *recListener) OnFileOffer(pid, nick, fn string, size int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.offers = append(r.offers, recordedOffer{pid, nick, fn, size})
}
func (r *recListener) OnFileProgress(pid, nick, fn string, p float64, up bool) {
	atomic.AddInt32(&r.progress, 1)
}
func (r *recListener) OnFileReceived(pid, nick, fn, path string, size int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.received = append(r.received, recordedReceived{pid, nick, fn, path, size})
}
func (r *recListener) OnFileComplete(pid, nick, fn string, ok bool, msg string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.complete = append(r.complete, recordedComplete{pid, nick, fn, msg, ok})
}
func (r *recListener) OnLog(level, format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.logs = append(r.logs, fmt.Sprintf("[%s] "+format, append([]any{level}, args...)...))
}
func (r *recListener) OnContactUpdate() { atomic.AddInt32(&r.updates, 1) }
func (r *recListener) OnChatChanged(pid, nick string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.chatChanges = append(r.chatChanges, pid+"|"+nick)
}

func (r *recListener) numMessages() int  { r.mu.Lock(); defer r.mu.Unlock(); return len(r.messages) }
func (r *recListener) numOffers() int    { r.mu.Lock(); defer r.mu.Unlock(); return len(r.offers) }
func (r *recListener) numReceived() int  { r.mu.Lock(); defer r.mu.Unlock(); return len(r.received) }
func (r *recListener) numComplete() int  { r.mu.Lock(); defer r.mu.Unlock(); return len(r.complete) }
func (r *recListener) lastMessage() recordedMsg {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.messages[len(r.messages)-1]
}
func (r *recListener) lastReceived() recordedReceived {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.received[len(r.received)-1]
}

// ------------------------------------------------------------------
// Test harness: two nodes wired via mocknet
// ------------------------------------------------------------------

type testPeer struct {
	node     *Node
	naclPub  [32]byte
	listener *recListener
}

// newTestPeer builds a minimal *Node around a real libp2p host.
// Skips DHT, presence, advertise, keepalive, identity save.
func newTestPeer(t *testing.T, h host.Host, nick string) *testPeer {
	t.Helper()
	pub, _, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	list := &recListener{}
	n := &Node{
		host:         h,
		nickname:     nick,
		naclPublic:   *pub,
		contacts:     make(map[peer.ID]*Contact),
		nickMap:      make(map[string]peer.ID),
		ctx:          ctx,
		cancel:       cancel,
		presenceChan: make(chan peer.ID, 100),
		listener:     list,
		password:     "", // disable disk writes (SaveContacts / saveIdentity no-op on empty pw)
	}
	h.SetStreamHandler(ProtocolID, n.handleStream)
	h.SetStreamHandler(AudioProtocolID, n.handleAudioStream)
	h.SetStreamHandler(VideoProtocolID, n.handleVideoStream)
	return &testPeer{node: n, naclPub: *pub, listener: list}
}

// mutualAdd: register `other` as a contact of `me` (with nickname `asNick`).
// Also copies addresses to peerstore so NewStream works.
func mutualAdd(me, other *testPeer, asNick string) {
	c := &Contact{
		Nickname:   asNick,
		PeerID:     other.node.host.ID(),
		PublicKey:  other.naclPub,
		SeenNonces: make(map[int64]time.Time),
		State:      StateIdle,
		Presence:   PresenceUnknown,
	}
	me.node.mu.Lock()
	me.node.contacts[c.PeerID] = c
	me.node.nickMap[asNick] = c.PeerID
	me.node.mu.Unlock()
	me.node.host.Peerstore().AddAddrs(
		other.node.host.ID(),
		other.node.host.Addrs(),
		peerstore.PermanentAddrTTL,
	)
}

// setupPair wires Alice and Bob via mocknet, mutually adds them as contacts.
func setupPair(t *testing.T) (alice, bob *testPeer) {
	t.Helper()
	chdirTemp(t) // so any stray file ops go to tempdir
	mn := mocknet.New()
	h1, err := mn.GenPeer()
	if err != nil {
		t.Fatal(err)
	}
	h2, err := mn.GenPeer()
	if err != nil {
		t.Fatal(err)
	}
	if err := mn.LinkAll(); err != nil {
		t.Fatal(err)
	}
	if err := mn.ConnectAllButSelf(); err != nil {
		t.Fatal(err)
	}
	alice = newTestPeer(t, h1, "alice")
	bob = newTestPeer(t, h2, "bob")

	// Alice knows Bob as "bob"; Bob knows Alice as "alice"
	mutualAdd(alice, bob, "bob")
	mutualAdd(bob, alice, "alice")

	t.Cleanup(func() {
		alice.node.cancel()
		bob.node.cancel()
		_ = h1.Close()
		_ = h2.Close()
	})
	return
}

func waitFor(t *testing.T, desc string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for: %s", desc)
}

func contact(p *testPeer, pid peer.ID) *Contact {
	p.node.mu.RLock()
	defer p.node.mu.RUnlock()
	return p.node.contacts[pid]
}

func getState(p *testPeer, pid peer.ID) ChatState {
	c := contact(p, pid)
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.State
}

func sessionEstablished(p *testPeer, pid peer.ID) bool {
	c := contact(p, pid)
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sessionEstab
}

// doHandshakeAndAccept runs the full flow: alice initiates, bob accepts.
// Returns once both sides show StateActive.
func doHandshakeAndAccept(t *testing.T, alice, bob *testPeer) {
	t.Helper()
	aliceID := alice.node.host.ID()
	bobID := bob.node.host.ID()

	go alice.node.InitConnect("bob")

	// Wait for Bob to see incoming request
	waitFor(t, "bob sees incoming request", 5*time.Second, func() bool {
		return getState(bob, aliceID) == StatePendingIncoming
	})

	bob.node.HandleDecision("alice", true)

	waitFor(t, "alice active", 5*time.Second, func() bool {
		return getState(alice, bobID) == StateActive
	})
	waitFor(t, "bob active", 5*time.Second, func() bool {
		return getState(bob, aliceID) == StateActive
	})
}

// ------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------

func TestStream_Mocknet_Setup(t *testing.T) {
	alice, bob := setupPair(t)
	if alice.node.host.ID() == bob.node.host.ID() {
		t.Fatal("same ID")
	}
}

func TestStream_BothConnected(t *testing.T) {
	alice, bob := setupPair(t)
	if len(alice.node.host.Network().Peers()) == 0 {
		t.Fatal("alice not connected to bob")
	}
	if len(bob.node.host.Network().Peers()) == 0 {
		t.Fatal("bob not connected to alice")
	}
}

func TestStream_Handshake_EstablishesSession(t *testing.T) {
	alice, bob := setupPair(t)
	aliceID := alice.node.host.ID()
	bobID := bob.node.host.ID()

	go alice.node.InitConnect("bob")

	waitFor(t, "alice session", 5*time.Second, func() bool {
		return sessionEstablished(alice, bobID)
	})
	waitFor(t, "bob session", 5*time.Second, func() bool {
		return sessionEstablished(bob, aliceID)
	})
}

func TestStream_Request_SetsBobPending(t *testing.T) {
	alice, bob := setupPair(t)
	aliceID := alice.node.host.ID()
	go alice.node.InitConnect("bob")
	waitFor(t, "bob pending", 5*time.Second, func() bool {
		return getState(bob, aliceID) == StatePendingIncoming
	})
}

func TestStream_Accept_BothActive(t *testing.T) {
	alice, bob := setupPair(t)
	doHandshakeAndAccept(t, alice, bob)
}

func TestStream_Decline_ClosesSession(t *testing.T) {
	alice, bob := setupPair(t)
	aliceID := alice.node.host.ID()
	bobID := bob.node.host.ID()

	go alice.node.InitConnect("bob")
	waitFor(t, "bob pending", 5*time.Second, func() bool {
		return getState(bob, aliceID) == StatePendingIncoming
	})

	bob.node.HandleDecision("alice", false)

	waitFor(t, "alice stream closed", 5*time.Second, func() bool {
		c := contact(alice, bobID)
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.Stream == nil
	})
}

func TestStream_TextMessage_AliceToBob(t *testing.T) {
	alice, bob := setupPair(t)
	bobID := bob.node.host.ID()

	doHandshakeAndAccept(t, alice, bob)

	alice.node.SendChatMessage(bobID, "hello from alice")

	waitFor(t, "bob receives", 5*time.Second, func() bool {
		return bob.listener.numMessages() >= 1
	})

	got := bob.listener.lastMessage()
	if got.Text != "hello from alice" {
		t.Fatalf("got %q", got.Text)
	}
}

func TestStream_TextMessage_BobToAlice(t *testing.T) {
	alice, bob := setupPair(t)
	aliceID := alice.node.host.ID()

	doHandshakeAndAccept(t, alice, bob)

	// clear alice's prior listener state
	alice.listener.mu.Lock()
	alice.listener.messages = nil
	alice.listener.mu.Unlock()

	bob.node.SendChatMessage(aliceID, "hi alice")

	waitFor(t, "alice receives", 5*time.Second, func() bool {
		return alice.listener.numMessages() >= 1
	})
	if alice.listener.lastMessage().Text != "hi alice" {
		t.Fatalf("got %q", alice.listener.lastMessage().Text)
	}
}

func TestStream_TextMessage_EmojiUnicode(t *testing.T) {
	alice, bob := setupPair(t)
	bobID := bob.node.host.ID()
	doHandshakeAndAccept(t, alice, bob)

	want := "Привет, 世界! 🔐"
	alice.node.SendChatMessage(bobID, want)

	waitFor(t, "bob receives", 5*time.Second, func() bool {
		return bob.listener.numMessages() >= 1
	})
	if bob.listener.lastMessage().Text != want {
		t.Fatalf("got %q want %q", bob.listener.lastMessage().Text, want)
	}
}

func TestStream_TextMessage_Bidirectional_10(t *testing.T) {
	alice, bob := setupPair(t)
	aliceID := alice.node.host.ID()
	bobID := bob.node.host.ID()
	doHandshakeAndAccept(t, alice, bob)

	for i := 0; i < 10; i++ {
		alice.node.SendChatMessage(bobID, fmt.Sprintf("a%d", i))
		time.Sleep(2 * time.Millisecond)
		bob.node.SendChatMessage(aliceID, fmt.Sprintf("b%d", i))
		time.Sleep(2 * time.Millisecond)
	}

	waitFor(t, "bob has 10", 10*time.Second, func() bool {
		return bob.listener.numMessages() >= 10
	})
	waitFor(t, "alice has 10", 10*time.Second, func() bool {
		return alice.listener.numMessages() >= 10
	})
}

func TestStream_TextMessage_LongBurst(t *testing.T) {
	alice, bob := setupPair(t)
	bobID := bob.node.host.ID()
	doHandshakeAndAccept(t, alice, bob)

	const N = 50
	for i := 0; i < N; i++ {
		alice.node.SendChatMessage(bobID, fmt.Sprintf("burst-%d", i))
		time.Sleep(time.Millisecond)
	}
	waitFor(t, fmt.Sprintf("bob receives %d", N), 15*time.Second, func() bool {
		return bob.listener.numMessages() >= N
	})
}

func TestStream_TextMessage_PreservesOrder(t *testing.T) {
	alice, bob := setupPair(t)
	bobID := bob.node.host.ID()
	doHandshakeAndAccept(t, alice, bob)

	const N = 20
	for i := 0; i < N; i++ {
		alice.node.SendChatMessage(bobID, fmt.Sprintf("%d", i))
		time.Sleep(time.Millisecond)
	}
	waitFor(t, "all received", 10*time.Second, func() bool {
		return bob.listener.numMessages() >= N
	})
	bob.listener.mu.Lock()
	defer bob.listener.mu.Unlock()
	for i, m := range bob.listener.messages[:N] {
		if m.Text != fmt.Sprintf("%d", i) {
			t.Fatalf("msg %d: got %q", i, m.Text)
		}
	}
}

func TestStream_DoubleRatchet_KeyRotatesAcrossMessages(t *testing.T) {
	alice, bob := setupPair(t)
	aliceID := alice.node.host.ID()
	bobID := bob.node.host.ID()
	doHandshakeAndAccept(t, alice, bob)

	// Bob's DH key (as seen by Alice) rotates only when Bob receives a new
	// key from Alice and replies. Drive a round-trip: A→B→A.
	aliceCon := contact(alice, bobID)
	aliceCon.mu.Lock()
	bobKeyBefore := *aliceCon.Ratchet.DHRemotePub
	aliceCon.mu.Unlock()

	// Note: SendChatMessage echoes back to the sender's own listener, so
	// after Alice sends "one" her listener already has 1 msg. To detect
	// Bob's reply we need >=2.
	alice.node.SendChatMessage(bobID, "one")
	waitFor(t, "bob gets one", 5*time.Second, func() bool {
		return bob.listener.numMessages() >= 1
	})
	bob.node.SendChatMessage(aliceID, "reply")
	waitFor(t, "alice gets reply", 5*time.Second, func() bool {
		return alice.listener.numMessages() >= 2
	})

	aliceCon.mu.Lock()
	bobKeyAfter := *aliceCon.Ratchet.DHRemotePub
	aliceCon.mu.Unlock()

	if bobKeyBefore == bobKeyAfter {
		t.Fatal("bob DH key should rotate after A→B→A round-trip")
	}
}

func TestStream_Disconnect_Active(t *testing.T) {
	alice, bob := setupPair(t)
	aliceID := alice.node.host.ID()
	bobID := bob.node.host.ID()
	doHandshakeAndAccept(t, alice, bob)

	alice.node.Disconnect("bob")

	waitFor(t, "alice stream closed", 5*time.Second, func() bool {
		c := contact(alice, bobID)
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.Stream == nil && c.State == StateIdle
	})
	waitFor(t, "bob stream closed", 5*time.Second, func() bool {
		c := contact(bob, aliceID)
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.Stream == nil && c.State == StateIdle
	})
}

func TestStream_Disconnect_NoContact_NoPanic(t *testing.T) {
	alice, _ := setupPair(t)
	// Should just log error, not panic
	alice.node.Disconnect("nobody")
}

func TestStream_RemoveFriend_DropsContact(t *testing.T) {
	alice, bob := setupPair(t)
	doHandshakeAndAccept(t, alice, bob)

	alice.node.RemoveFriend("bob")

	alice.node.mu.RLock()
	_, exists := alice.node.nickMap["bob"]
	alice.node.mu.RUnlock()
	if exists {
		t.Fatal("bob still in nickMap")
	}
}

func TestStream_LogoutSendsBye(t *testing.T) {
	alice, bob := setupPair(t)
	aliceID := alice.node.host.ID()
	doHandshakeAndAccept(t, alice, bob)

	alice.node.Logout()

	waitFor(t, "bob sees disconnect", 5*time.Second, func() bool {
		c := contact(bob, aliceID)
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.Stream == nil
	})
	if alice.node.IsLoggedIn() {
		t.Fatal("still logged in")
	}
}

func TestStream_IsLoggedIn(t *testing.T) {
	alice, _ := setupPair(t)
	if !alice.node.IsLoggedIn() {
		t.Fatal("should be logged in")
	}
}

func TestStream_GetContacts(t *testing.T) {
	alice, _ := setupPair(t)
	cs := alice.node.GetContacts()
	if len(cs) != 1 || cs[0].Nickname != "bob" {
		t.Fatalf("got %v", cs)
	}
}

func TestStream_GetHostID(t *testing.T) {
	alice, _ := setupPair(t)
	if alice.node.GetHostID() != alice.node.host.ID().String() {
		t.Fatal("mismatch")
	}
}

func TestStream_GetNickname(t *testing.T) {
	alice, _ := setupPair(t)
	if alice.node.GetNickname() != "alice" {
		t.Fatal("wrong nick")
	}
}

func TestStream_EnterLeaveChat(t *testing.T) {
	alice, bob := setupPair(t)
	bobID := bob.node.host.ID()
	doHandshakeAndAccept(t, alice, bob)

	if alice.node.GetActiveChat() != bobID {
		t.Fatal("expected active chat with bob")
	}

	alice.node.LeaveChat()
	waitFor(t, "chat cleared", 2*time.Second, func() bool {
		return alice.node.GetActiveChat() == ""
	})
}

func TestStream_SendChatMessage_NoActive_NoPanic(t *testing.T) {
	alice, bob := setupPair(t)
	bobID := bob.node.host.ID()
	// No handshake → state is Idle → should just log warning
	alice.node.SendChatMessage(bobID, "hello")
	// no panic = success
	if bob.listener.numMessages() != 0 {
		t.Fatal("should not have delivered")
	}
}

// ------------------------------------------------------------------
// File transfer over real streams
// ------------------------------------------------------------------

func makeFile(t *testing.T, dir, name string, content []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, content, 0644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestStream_FileOffer_DeliversToReceiver(t *testing.T) {
	alice, bob := setupPair(t)
	bobID := bob.node.host.ID()
	doHandshakeAndAccept(t, alice, bob)

	srcDir, _ := os.MkdirTemp("", "src-*")
	t.Cleanup(func() { os.RemoveAll(srcDir) })
	path := makeFile(t, srcDir, "hello.txt", []byte("small file content"))

	if err := alice.node.SendFile(bobID, path); err != nil {
		t.Fatal(err)
	}

	waitFor(t, "bob offer", 5*time.Second, func() bool {
		return bob.listener.numOffers() >= 1
	})
	if bob.listener.offers[0].Name != "hello.txt" {
		t.Fatalf("got %q", bob.listener.offers[0].Name)
	}
}

func TestStream_FileTransfer_SmallFile(t *testing.T) {
	alice, bob := setupPair(t)
	bobID := bob.node.host.ID()
	doHandshakeAndAccept(t, alice, bob)

	srcDir, _ := os.MkdirTemp("", "src-*")
	t.Cleanup(func() { os.RemoveAll(srcDir) })
	content := []byte("hello over real stream!\nline two.\n")
	path := makeFile(t, srcDir, "msg.txt", content)

	if err := alice.node.SendFile(bobID, path); err != nil {
		t.Fatal(err)
	}

	waitFor(t, "bob offer", 5*time.Second, func() bool {
		return bob.listener.numOffers() >= 1
	})
	if err := bob.node.AcceptFile("alice"); err != nil {
		t.Fatal(err)
	}

	waitFor(t, "bob received", 10*time.Second, func() bool {
		return bob.listener.numReceived() >= 1
	})

	rec := bob.listener.lastReceived()
	got, err := os.ReadFile(rec.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("content mismatch\ngot:  %q\nwant: %q", got, content)
	}
	if rec.Size != int64(len(content)) {
		t.Fatalf("size %d want %d", rec.Size, len(content))
	}
}

func TestStream_FileTransfer_MultiChunk(t *testing.T) {
	alice, bob := setupPair(t)
	bobID := bob.node.host.ID()
	doHandshakeAndAccept(t, alice, bob)

	// Make file spanning multiple chunks
	content := make([]byte, FileChunkSize*3+1234)
	if _, err := rand.Read(content); err != nil {
		t.Fatal(err)
	}

	srcDir, _ := os.MkdirTemp("", "src-*")
	t.Cleanup(func() { os.RemoveAll(srcDir) })
	path := makeFile(t, srcDir, "chunked.bin", content)

	if err := alice.node.SendFile(bobID, path); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "bob offer", 5*time.Second, func() bool {
		return bob.listener.numOffers() >= 1
	})
	if err := bob.node.AcceptFile("alice"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "bob received", 20*time.Second, func() bool {
		return bob.listener.numReceived() >= 1
	})

	rec := bob.listener.lastReceived()
	got, err := os.ReadFile(rec.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("content mismatch (sizes got=%d want=%d)", len(got), len(content))
	}
}

func TestStream_FileTransfer_Decline(t *testing.T) {
	alice, bob := setupPair(t)
	bobID := bob.node.host.ID()
	doHandshakeAndAccept(t, alice, bob)

	srcDir, _ := os.MkdirTemp("", "src-*")
	t.Cleanup(func() { os.RemoveAll(srcDir) })
	path := makeFile(t, srcDir, "rejected.txt", []byte("nope"))

	if err := alice.node.SendFile(bobID, path); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "bob offer", 5*time.Second, func() bool {
		return bob.listener.numOffers() >= 1
	})
	if err := bob.node.DeclineFile("alice"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "alice complete=false", 5*time.Second, func() bool {
		return alice.listener.numComplete() >= 1
	})
	if alice.listener.complete[0].Success {
		t.Fatal("expected failure")
	}
}

func TestStream_FileTransfer_SenderCancel(t *testing.T) {
	alice, bob := setupPair(t)
	bobID := bob.node.host.ID()
	doHandshakeAndAccept(t, alice, bob)

	srcDir, _ := os.MkdirTemp("", "src-*")
	t.Cleanup(func() { os.RemoveAll(srcDir) })
	path := makeFile(t, srcDir, "cancel.bin", []byte("data"))

	if err := alice.node.SendFile(bobID, path); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "bob offer", 5*time.Second, func() bool {
		return bob.listener.numOffers() >= 1
	})
	// Alice cancels her own outgoing offer
	if err := alice.node.DeclineFile("bob"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "bob complete fail", 5*time.Second, func() bool {
		return bob.listener.numComplete() >= 1
	})
}

func TestStream_FileTransfer_SendTwiceWhileBusy_Fails(t *testing.T) {
	alice, bob := setupPair(t)
	bobID := bob.node.host.ID()
	doHandshakeAndAccept(t, alice, bob)

	srcDir, _ := os.MkdirTemp("", "src-*")
	t.Cleanup(func() { os.RemoveAll(srcDir) })
	p1 := makeFile(t, srcDir, "a.bin", []byte("one"))

	if err := alice.node.SendFile(bobID, p1); err != nil {
		t.Fatal(err)
	}
	// Immediately try another — should fail "already have pending"
	if err := alice.node.SendFile(bobID, p1); err == nil {
		t.Fatal("want error on concurrent SendFile")
	}
}

func TestStream_FileTransfer_SendMissingFile_Fails(t *testing.T) {
	alice, bob := setupPair(t)
	bobID := bob.node.host.ID()
	doHandshakeAndAccept(t, alice, bob)

	if err := alice.node.SendFile(bobID, "/definitely/does/not/exist.xyz"); err == nil {
		t.Fatal("want error")
	}
}

func TestStream_FileTransfer_SendDir_Fails(t *testing.T) {
	alice, bob := setupPair(t)
	bobID := bob.node.host.ID()
	doHandshakeAndAccept(t, alice, bob)

	dir := t.TempDir()
	if err := alice.node.SendFile(bobID, dir); err == nil {
		t.Fatal("want error")
	}
}

func TestStream_FileTransfer_SendWithoutChat_Fails(t *testing.T) {
	alice, bob := setupPair(t)
	bobID := bob.node.host.ID()
	_ = bob
	// No handshake yet → state is Idle
	srcDir, _ := os.MkdirTemp("", "src-*")
	t.Cleanup(func() { os.RemoveAll(srcDir) })
	p := makeFile(t, srcDir, "f.bin", []byte("x"))
	if err := alice.node.SendFile(bobID, p); err == nil {
		t.Fatal("want error (chat not active)")
	}
}

func TestStream_FileTransfer_DoubleOffer_AutoDeclinesSecond(t *testing.T) {
	alice, bob := setupPair(t)
	bobID := bob.node.host.ID()
	doHandshakeAndAccept(t, alice, bob)

	srcDir, _ := os.MkdirTemp("", "src-*")
	t.Cleanup(func() { os.RemoveAll(srcDir) })
	p := makeFile(t, srcDir, "a.bin", []byte("one"))

	if err := alice.node.SendFile(bobID, p); err != nil {
		t.Fatal(err)
	}
	// Bob already has a pending; a second offer from Alice requires Alice to
	// cancel first. Confirm Bob's listener only got one offer for now.
	time.Sleep(100 * time.Millisecond)
	if bob.listener.numOffers() != 1 {
		t.Fatalf("expected 1 offer, got %d", bob.listener.numOffers())
	}
}

func TestStream_AcceptFile_NoPending_Fails(t *testing.T) {
	alice, bob := setupPair(t)
	doHandshakeAndAccept(t, alice, bob)

	if err := bob.node.AcceptFile("alice"); err == nil {
		t.Fatal("want error")
	}
}

func TestStream_HasPendingFile_NoChat(t *testing.T) {
	alice, _ := setupPair(t)
	has, _, _, _ := alice.node.HasPendingFile()
	if has {
		t.Fatal("should not")
	}
}

func TestStream_HasPendingFile_AfterOffer(t *testing.T) {
	alice, bob := setupPair(t)
	bobID := bob.node.host.ID()
	doHandshakeAndAccept(t, alice, bob)

	srcDir, _ := os.MkdirTemp("", "src-*")
	t.Cleanup(func() { os.RemoveAll(srcDir) })
	p := makeFile(t, srcDir, "a.bin", []byte("data"))
	if err := alice.node.SendFile(bobID, p); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "pending on alice", 3*time.Second, func() bool {
		has, out, _, _ := alice.node.HasPendingFile()
		return has && out
	})
}

func TestStream_GetIdentityString_Format(t *testing.T) {
	alice, _ := setupPair(t)
	s := alice.node.GetIdentityString()
	if len(s) < 10 || s[:11] != ".addfriend " {
		t.Fatalf("got %q", s)
	}
}

func TestStream_AddFriend_Rejects_Self(t *testing.T) {
	alice, _ := setupPair(t)
	before := len(alice.node.GetContacts())
	// Attempt to add self: should log error but not panic, and not create contact
	selfID := alice.node.host.ID().String()
	alice.node.AddFriend("selfnick", selfID, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	after := len(alice.node.GetContacts())
	if after != before {
		t.Fatalf("contacts changed %d→%d", before, after)
	}
}

func TestStream_AddFriend_DuplicateNick_Fails(t *testing.T) {
	alice, bob := setupPair(t)
	// try adding another contact under nickname "bob"
	bobPubB64 := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	other := bob.node.host.ID().String()
	before := len(alice.node.GetContacts())
	alice.node.AddFriend("bob", other, bobPubB64)
	after := len(alice.node.GetContacts())
	if after != before {
		t.Fatalf("should not add duplicate")
	}
}

func TestStream_Handshake_WrongPublicKey_Fails(t *testing.T) {
	// Alice's contact record for Bob has the WRONG NaCl pubkey.
	// Bob's signed handshake carries Bob's actual pubkey → key mismatch on Alice side.
	chdirTemp(t)
	mn := mocknet.New()
	h1, _ := mn.GenPeer()
	h2, _ := mn.GenPeer()
	mn.LinkAll()
	mn.ConnectAllButSelf()
	alice := newTestPeer(t, h1, "alice")
	bob := newTestPeer(t, h2, "bob")

	// Corrupted pubkey for bob in alice's contact list
	var wrong [32]byte
	wrong[0] = 0xFF
	alice.node.mu.Lock()
	c := &Contact{
		Nickname:   "bob",
		PeerID:     h2.ID(),
		PublicKey:  wrong,
		SeenNonces: make(map[int64]time.Time),
		State:      StateIdle,
	}
	alice.node.contacts[h2.ID()] = c
	alice.node.nickMap["bob"] = h2.ID()
	alice.node.mu.Unlock()
	alice.node.host.Peerstore().AddAddrs(h2.ID(), h2.Addrs(), peerstore.PermanentAddrTTL)

	// Bob knows alice correctly (so his side won't fail)
	mutualAdd(bob, alice, "alice")

	go alice.node.InitConnect("bob")

	// Handshake must fail; wait a bit and confirm session never establishes.
	time.Sleep(500 * time.Millisecond)
	if sessionEstablished(alice, h2.ID()) {
		t.Fatal("session should not establish with wrong pubkey")
	}

	t.Cleanup(func() {
		alice.node.cancel()
		bob.node.cancel()
		h1.Close()
		h2.Close()
	})
}

func TestStream_ContactUpdate_Fires(t *testing.T) {
	alice, bob := setupPair(t)
	start := atomic.LoadInt32(&alice.listener.updates)
	doHandshakeAndAccept(t, alice, bob)
	if atomic.LoadInt32(&alice.listener.updates) <= start {
		t.Fatal("OnContactUpdate not called")
	}
}

func TestStream_ChatChanged_FiresOnEnter(t *testing.T) {
	alice, bob := setupPair(t)
	doHandshakeAndAccept(t, alice, bob)
	alice.listener.mu.Lock()
	n := len(alice.listener.chatChanges)
	alice.listener.mu.Unlock()
	if n == 0 {
		t.Fatal("expected at least one ChatChanged event")
	}
}

func TestStream_Ping_Sent_AfterEstablish(t *testing.T) {
	// We don't run keepAliveLoop in the test, so this just tests that
	// the plumbing for MsgTypePing at least builds: send a Ping, recipient
	// should not surface anything in listener (pings are ignored).
	alice, bob := setupPair(t)
	doHandshakeAndAccept(t, alice, bob)
	c := contact(alice, bob.node.host.ID())
	if err := alice.node.sendSessionMessage(c, MsgTypePing, nil); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	// No message should be user-visible
	// (only the request/accept flow ones, which happened in doHandshakeAndAccept)
	// So bob.listener.messages must be 0 for text.
	if bob.listener.numMessages() != 0 {
		t.Fatalf("ping leaked as message: %d", bob.listener.numMessages())
	}
}

// ------------------------------------------------------------------
// SAS (Short Authentication String) verification
// ------------------------------------------------------------------

func TestStream_SAS_BothSidesMatch(t *testing.T) {
	alice, bob := setupPair(t)
	doHandshakeAndAccept(t, alice, bob)

	aliceSAS := alice.node.GetSASCode("bob")
	bobSAS := bob.node.GetSASCode("alice")

	if aliceSAS == "" || bobSAS == "" {
		t.Fatalf("empty SAS: alice=%q bob=%q", aliceSAS, bobSAS)
	}
	if aliceSAS != bobSAS {
		t.Fatalf("SAS mismatch! alice=%q bob=%q (honest session must produce identical SAS)", aliceSAS, bobSAS)
	}
	t.Logf("honest session SAS = %s", aliceSAS)
}

func TestStream_SAS_DifferentPerSession(t *testing.T) {
	// Each session has fresh ephemerals, so disconnect+reconnect must yield a new SAS.
	alice, bob := setupPair(t)
	doHandshakeAndAccept(t, alice, bob)

	sas1 := alice.node.GetSASCode("bob")

	// Tear down, reconnect.
	alice.node.Disconnect("bob")
	waitFor(t, "disconnect completes", 3*time.Second, func() bool {
		return alice.node.GetSASCode("bob") == ""
	})
	// Respect the handshake-cooldown on Bob's side (500ms) — a legitimate
	// user-initiated reconnect just has to wait past the flood window.
	time.Sleep(HandshakeCooldown + 100*time.Millisecond)
	doHandshakeAndAccept(t, alice, bob)
	sas2 := alice.node.GetSASCode("bob")

	if sas1 == sas2 {
		t.Fatalf("SAS must rotate per session, got %q both times", sas1)
	}
}

func TestStream_SAS_EmptyWithoutSession(t *testing.T) {
	alice, _ := setupPair(t)
	if sas := alice.node.GetSASCode("bob"); sas != "" {
		t.Fatalf("expected empty SAS without session, got %q", sas)
	}
}

func TestStream_SAS_EmptyForUnknownContact(t *testing.T) {
	alice, _ := setupPair(t)
	if sas := alice.node.GetSASCode("nobody"); sas != "" {
		t.Fatalf("expected empty SAS for unknown contact, got %q", sas)
	}
}

// TestStream_SAS_MITM_ProducesDifferentCodes simulates a classic MITM:
// Alice and Bob independently set up sessions with a *different* third party
// (the "attacker"). Since Alice's peer ephemeral and Bob's peer ephemeral
// differ, the SAS they would see MUST differ — the whole point of OOB
// verification.
func TestStream_SAS_MITM_ProducesDifferentCodes(t *testing.T) {
	chdirTemp(t)
	mn := mocknet.New()
	hAlice, _ := mn.GenPeer()
	hBob, _ := mn.GenPeer()
	hMallory, _ := mn.GenPeer()
	if err := mn.LinkAll(); err != nil {
		t.Fatal(err)
	}
	if err := mn.ConnectAllButSelf(); err != nil {
		t.Fatal(err)
	}

	alice := newTestPeer(t, hAlice, "alice")
	bob := newTestPeer(t, hBob, "bob")
	mallory := newTestPeer(t, hMallory, "mallory")

	// Alice thinks she's talking to "bob" but actually connects to Mallory
	// (who impersonates Bob in Alice's contact list).
	mutualAdd(alice, mallory, "bob") // ← Mallory registered as "bob" on Alice's side
	mutualAdd(mallory, alice, "alice")

	// Bob meanwhile has a separate honest session with Mallory (posing as alice).
	mutualAdd(bob, mallory, "alice")
	mutualAdd(mallory, bob, "bob")

	// Session A: Alice ↔ Mallory
	go alice.node.InitConnect("bob") // dials Mallory
	waitFor(t, "mallory sees pending from alice", 5*time.Second, func() bool {
		return getState(mallory, hAlice.ID()) == StatePendingIncoming
	})
	mallory.node.HandleDecision("alice", true)
	waitFor(t, "alice session up", 5*time.Second, func() bool {
		return alice.node.GetSASCode("bob") != ""
	})

	// Session B: Mallory ↔ Bob
	go mallory.node.InitConnect("bob")
	waitFor(t, "bob sees pending from mallory", 5*time.Second, func() bool {
		return getState(bob, hMallory.ID()) == StatePendingIncoming
	})
	bob.node.HandleDecision("alice", true)
	waitFor(t, "bob session up", 5*time.Second, func() bool {
		return bob.node.GetSASCode("alice") != ""
	})

	aliceSAS := alice.node.GetSASCode("bob")
	bobSAS := bob.node.GetSASCode("alice")

	if aliceSAS == bobSAS {
		t.Fatalf("SAS collision under MITM! alice=%q bob=%q — attack would succeed silently", aliceSAS, bobSAS)
	}
	t.Logf("MITM detected via SAS: alice sees %s, bob sees %s", aliceSAS, bobSAS)

	t.Cleanup(func() {
		alice.node.cancel()
		bob.node.cancel()
		mallory.node.cancel()
		hAlice.Close()
		hBob.Close()
		hMallory.Close()
	})
}

// ------------------------------------------------------------------
// QR invite
// ------------------------------------------------------------------

func TestStream_QR_GeneratedForLoggedInUser(t *testing.T) {
	alice, _ := setupPair(t)
	qr, err := alice.node.GenerateInviteQR()
	if err != nil {
		t.Fatal(err)
	}
	if qr == "" {
		t.Fatal("empty QR string")
	}
	// ToSmallString uses half-block characters (▀ ▄ █). Sanity: should be non-trivial.
	if len(qr) < 100 {
		t.Fatalf("QR suspiciously short (%d bytes)", len(qr))
	}
}

func TestStream_QR_FailsWhenNotLoggedIn(t *testing.T) {
	alice, _ := setupPair(t)
	alice.node.mu.Lock()
	alice.node.nickname = ""
	alice.node.mu.Unlock()
	if _, err := alice.node.GenerateInviteQR(); err == nil {
		t.Fatal("expected error when not logged in")
	}
}

func TestStream_QR_EncodesInviteString(t *testing.T) {
	// Decoding QR back is out of scope (no decoder dep). Instead, verify
	// that changing the invite content changes the QR output.
	alice, _ := setupPair(t)
	qr1, _ := alice.node.GenerateInviteQR()

	// Force a different nickname → different invite → different QR.
	alice.node.mu.Lock()
	alice.node.nickname = "alice-renamed"
	alice.node.mu.Unlock()
	qr2, _ := alice.node.GenerateInviteQR()

	if qr1 == qr2 {
		t.Fatal("QR output should change with invite content")
	}
}

func TestStream_SelfEcho_UsesOwnPeerID(t *testing.T) {
	// SendChatMessage echoes the outgoing message to the sender's own
	// listener. The CLI distinguishes self-echo from incoming messages by
	// comparing peerID against its own host ID — so we must verify the
	// self-echo really carries the sender's host ID (not the recipient's).
	alice, bob := setupPair(t)
	aliceID := alice.node.host.ID()
	bobID := bob.node.host.ID()
	doHandshakeAndAccept(t, alice, bob)

	alice.listener.mu.Lock()
	alice.listener.messages = nil
	alice.listener.mu.Unlock()

	alice.node.SendChatMessage(bobID, "hello")

	waitFor(t, "alice self-echo", 5*time.Second, func() bool {
		return alice.listener.numMessages() >= 1
	})

	got := alice.listener.lastMessage()
	if got.PeerID != aliceID.String() {
		t.Fatalf("self-echo peerID = %q, want alice's %q", got.PeerID, aliceID.String())
	}
	if got.Text != "hello" {
		t.Fatalf("self-echo text = %q", got.Text)
	}
}

func TestStream_IncomingMessage_UsesRemotePeerID(t *testing.T) {
	// Incoming messages must carry the REMOTE peer's ID so the CLI can tell
	// them apart from self-echoes.
	alice, bob := setupPair(t)
	aliceID := alice.node.host.ID()
	bobID := bob.node.host.ID()
	doHandshakeAndAccept(t, alice, bob)

	bob.listener.mu.Lock()
	bob.listener.messages = nil
	bob.listener.mu.Unlock()

	alice.node.SendChatMessage(bobID, "hi")

	waitFor(t, "bob receives", 5*time.Second, func() bool {
		return bob.listener.numMessages() >= 1
	})

	got := bob.listener.lastMessage()
	if got.PeerID != aliceID.String() {
		t.Fatalf("incoming peerID = %q, want alice's %q", got.PeerID, aliceID.String())
	}
	if got.PeerID == bobID.String() {
		t.Fatal("incoming msg carries bob's own ID — self-echo logic would treat it as self!")
	}
}

func TestStream_FileTransfer_VoicemailRenamedOnReceive(t *testing.T) {
	// Sender records voicemail-5.wav (their 5th), receiver has none yet —
	// receiver should save it as voicemail-1.wav (their first).
	alice, bob := setupPair(t)
	bobID := bob.node.host.ID()
	doHandshakeAndAccept(t, alice, bob)

	// Fake a recording file on sender's side.
	srcDir, _ := os.MkdirTemp("", "src-*")
	t.Cleanup(func() { os.RemoveAll(srcDir) })
	path := makeFile(t, srcDir, "voicemail-5.wav", []byte("fake wav content"))

	if err := alice.node.SendFile(bobID, path); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "bob offer", 5*time.Second, func() bool {
		return bob.listener.numOffers() >= 1
	})
	if err := bob.node.AcceptFile("alice"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "bob receives", 10*time.Second, func() bool {
		return bob.listener.numReceived() >= 1
	})

	rec := bob.listener.lastReceived()
	// Bob's first voicemail → voicemail-1.wav, not voicemail-5.wav.
	if !strings.HasSuffix(rec.Path, "voicemail-1.wav") {
		t.Fatalf("expected voicemail-1.wav on receiver, got %q", rec.Path)
	}
}

func TestStream_FileTransfer_NonVoiceFile_NotRenamed(t *testing.T) {
	// A regular file (not matching voicemail-N.wav) must NOT be renamed.
	alice, bob := setupPair(t)
	bobID := bob.node.host.ID()
	doHandshakeAndAccept(t, alice, bob)

	srcDir, _ := os.MkdirTemp("", "src-*")
	t.Cleanup(func() { os.RemoveAll(srcDir) })
	path := makeFile(t, srcDir, "document.pdf", []byte("pdf content"))

	if err := alice.node.SendFile(bobID, path); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "bob offer", 5*time.Second, func() bool {
		return bob.listener.numOffers() >= 1
	})
	if err := bob.node.AcceptFile("alice"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "bob receives", 10*time.Second, func() bool {
		return bob.listener.numReceived() >= 1
	})

	rec := bob.listener.lastReceived()
	if !strings.HasSuffix(rec.Path, "document.pdf") {
		t.Fatalf("non-voice file was renamed to %q, should have stayed document.pdf", rec.Path)
	}
}

func TestStream_VoiceCall_OfferReachesCallee(t *testing.T) {
	// Alice calls Bob — Bob's contact.Call must go to CallIncoming.
	alice, bob := setupPair(t)
	aliceID := alice.node.host.ID()
	doHandshakeAndAccept(t, alice, bob)

	if err := alice.node.InitiateCall("bob"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "bob receives call offer", 5*time.Second, func() bool {
		c := contact(bob, aliceID)
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.Call != nil && c.Call.State == CallIncoming
	})
}

func TestStream_VoiceCall_DeclinePropagates(t *testing.T) {
	alice, bob := setupPair(t)
	aliceID := alice.node.host.ID()
	bobID := bob.node.host.ID()
	doHandshakeAndAccept(t, alice, bob)

	if err := alice.node.InitiateCall("bob"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "bob incoming", 5*time.Second, func() bool {
		c := contact(bob, aliceID)
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.Call != nil && c.Call.State == CallIncoming
	})

	if err := bob.node.DeclineCall("alice"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "alice sees decline", 5*time.Second, func() bool {
		c := contact(alice, bobID)
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.Call == nil
	})
}

func TestStream_VoiceCall_StateIdleBeforeAnyOffer(t *testing.T) {
	alice, bob := setupPair(t)
	bobID := bob.node.host.ID()
	doHandshakeAndAccept(t, alice, bob)
	c := contact(alice, bobID)
	c.mu.Lock()
	has := c.Call != nil
	c.mu.Unlock()
	if has {
		t.Fatal("CallSession should be nil before InitiateCall")
	}
}

func TestStream_VoiceCall_DoubleOfferRejected(t *testing.T) {
	alice, bob := setupPair(t)
	aliceID := alice.node.host.ID()
	doHandshakeAndAccept(t, alice, bob)

	if err := alice.node.InitiateCall("bob"); err != nil {
		t.Fatal(err)
	}
	if err := alice.node.InitiateCall("bob"); err == nil {
		t.Fatal("second InitiateCall should fail (call already active)")
	}
	_ = aliceID
}

func TestStream_VoiceCall_EndWithoutActive_Fails(t *testing.T) {
	alice, bob := setupPair(t)
	doHandshakeAndAccept(t, alice, bob)
	if err := alice.node.EndCall("bob"); err == nil {
		t.Fatal("EndCall should fail when no call in progress")
	}
}

func TestStream_VoiceCall_AcceptWithoutIncoming_Fails(t *testing.T) {
	alice, bob := setupPair(t)
	doHandshakeAndAccept(t, alice, bob)
	if err := alice.node.AcceptCall("bob"); err == nil {
		t.Fatal("AcceptCall should fail with no pending offer")
	}
}

func TestStream_VoiceCall_WorksWithoutActiveChat(t *testing.T) {
	// Calls are now independent of chat — no prior .connect required.
	// InitiateCall opens its own libp2p stream; the offer reaches bob
	// regardless of whether a chat session exists.
	alice, bob := setupPair(t)
	aliceID := alice.node.host.ID()
	// NO handshake — chat state stays Idle.
	if err := alice.node.InitiateCall("bob"); err != nil {
		t.Fatalf("InitiateCall should work without chat: %v", err)
	}
	waitFor(t, "bob sees incoming call without chat", 5*time.Second, func() bool {
		c := contact(bob, aliceID)
		if c == nil {
			return false
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.Call != nil && c.Call.State == CallIncoming
	})
}

func TestStream_TextMessage_AfterDH_Rotation(t *testing.T) {
	// After several DH rotations (bidirectional reply), messages still decrypt
	alice, bob := setupPair(t)
	aliceID := alice.node.host.ID()
	bobID := bob.node.host.ID()
	doHandshakeAndAccept(t, alice, bob)

	for i := 0; i < 5; i++ {
		alice.node.SendChatMessage(bobID, fmt.Sprintf("ping %d", i))
		time.Sleep(2 * time.Millisecond)
		bob.node.SendChatMessage(aliceID, fmt.Sprintf("pong %d", i))
		time.Sleep(2 * time.Millisecond)
	}

	waitFor(t, "bob got 5", 5*time.Second, func() bool {
		return bob.listener.numMessages() >= 5
	})
	waitFor(t, "alice got 5", 5*time.Second, func() bool {
		return alice.listener.numMessages() >= 5
	})
}
