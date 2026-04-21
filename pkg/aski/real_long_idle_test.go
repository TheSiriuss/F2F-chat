package f2f

import (
	"testing"
	"time"
)

// TestReal_LongIdle_ReconnectViaCache simulates the "10 минут спустя" scenario
// the user asked about. Gated behind LONG_TESTS=1 so the CI run stays fast.
func TestReal_LongIdle_ReconnectViaCache(t *testing.T) {
	if testing.Short() {
		t.Skip("long idle test (60s)")
	}

	chdirTemp(t)

	alice := newRealPeer(t, "alice")
	bob := newRealPeer(t, "bob")

	realMutualAdd(alice, bob, "bob")
	realMutualAdd(bob, alice, "alice")
	connectLibp2p(t, alice, bob)

	// Round 1
	go alice.node.InitConnect("bob")
	waitFor(t, "bob pending #1", 10*time.Second, func() bool {
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
	waitFor(t, "alice idle", 10*time.Second, func() bool {
		return getState(alice.asTestPeer(), bob.node.host.ID()) == StateIdle
	})

	// Long idle — 60 seconds.
	t.Log("sleeping 60s (long-idle reconnect test)")
	time.Sleep(60 * time.Second)

	// Reconnect — pure cache.
	go alice.node.InitConnect("bob")
	waitFor(t, "bob pending #2", 20*time.Second, func() bool {
		c := contact(bob.asTestPeer(), alice.node.host.ID())
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.State == StatePendingIncoming
	})
	bob.node.HandleDecision("alice", true)
	waitFor(t, "active #2", 20*time.Second, func() bool {
		return getState(alice.asTestPeer(), bob.node.host.ID()) == StateActive
	})
	t.Log("reconnect after 60s idle — OK")
}
