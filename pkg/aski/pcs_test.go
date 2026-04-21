package f2f

import (
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
)

// -----------------------------------------------------------------------------
// Post-Compromise Security — DH ratchet tests
//
// We verify:
//  1. After applyCallDHRatchet, ALL keys change (both voice and video, both
//     directions). If a pre-ratchet memory snapshot was taken, the new
//     keys are unobtainable from it.
//  2. Both sides compute matching keys from the same shared secret.
//  3. FS rotation counters reset after a DH ratchet (fresh chain root).
// -----------------------------------------------------------------------------

// buildTestCall returns a CallSession pre-populated with deterministic
// starting keys, ready for applyCallDHRatchet to be exercised.
func buildTestCall(aIsAlice bool) *CallSession {
	call := &CallSession{}
	// Put DIFFERENT bytes in each field so we can detect overlap bugs.
	for i := range call.sendKey {
		call.sendKey[i] = byte(0x10 + i)
	}
	for i := range call.recvKey {
		call.recvKey[i] = byte(0x20 + i)
	}
	for i := range call.videoSendKey {
		call.videoSendKey[i] = byte(0x30 + i)
	}
	for i := range call.videoRecvKey {
		call.videoRecvKey[i] = byte(0x40 + i)
	}
	call.sendGen = 5
	call.recvGen = 7
	call.videoSendGen = 3
	call.videoRecvGen = 4
	return call
}

func TestApplyCallDHRatchet_AllKeysChange(t *testing.T) {
	call := buildTestCall(true)
	prev := struct{ s, r, vs, vr [32]byte }{call.sendKey, call.recvKey, call.videoSendKey, call.videoRecvKey}

	var shared [32]byte
	for i := range shared {
		shared[i] = byte(i + 1)
	}

	alice := peer.ID("alice-peer-id-1234567890")
	bob := peer.ID("bob-peer-id-xxxxxxxxxxxxx")

	applyCallDHRatchet(call, shared, alice, bob)

	if call.sendKey == prev.s {
		t.Error("sendKey did not change")
	}
	if call.recvKey == prev.r {
		t.Error("recvKey did not change")
	}
	if call.videoSendKey == prev.vs {
		t.Error("videoSendKey did not change")
	}
	if call.videoRecvKey == prev.vr {
		t.Error("videoRecvKey did not change")
	}
}

func TestApplyCallDHRatchet_ResetsFSGenCounters(t *testing.T) {
	call := buildTestCall(true)
	var shared [32]byte
	shared[0] = 1
	applyCallDHRatchet(call, shared, peer.ID("a"), peer.ID("b"))
	if call.sendGen != 0 || call.recvGen != 0 {
		t.Fatalf("FS gen counters not reset: sendGen=%d, recvGen=%d", call.sendGen, call.recvGen)
	}
	if call.videoSendGen != 0 || call.videoRecvGen != 0 {
		t.Fatalf("video gen not reset: %d %d", call.videoSendGen, call.videoRecvGen)
	}
}

func TestApplyCallDHRatchet_BothSidesMatch(t *testing.T) {
	// Simulate Alice and Bob performing the ratchet with the same shared
	// secret. Their roles are swapped — Alice's sendKey must equal Bob's
	// recvKey (and vice versa) both before AND after the ratchet.
	alice := peer.ID("alice-aaaaaaaaaaaaaaaaaaa")
	bob := peer.ID("bob-bbbbbbbbbbbbbbbbbbbbbb")

	callA := buildTestCall(true)
	callB := buildTestCall(true)
	// Swap: Bob's recvKey = Alice's sendKey (and vice versa)
	callB.sendKey = callA.recvKey
	callB.recvKey = callA.sendKey
	callB.videoSendKey = callA.videoRecvKey
	callB.videoRecvKey = callA.videoSendKey

	var shared [32]byte
	for i := range shared {
		shared[i] = byte(0xAA ^ i)
	}

	applyCallDHRatchet(callA, shared, alice, bob)
	applyCallDHRatchet(callB, shared, bob, alice)

	if callA.sendKey != callB.recvKey {
		t.Error("alice.sendKey != bob.recvKey after ratchet")
	}
	if callA.recvKey != callB.sendKey {
		t.Error("alice.recvKey != bob.sendKey after ratchet")
	}
	if callA.videoSendKey != callB.videoRecvKey {
		t.Error("video send/recv keys desynced after ratchet")
	}
	if callA.videoRecvKey != callB.videoSendKey {
		t.Error("video recv/send keys desynced after ratchet")
	}
}

func TestApplyCallDHRatchet_DifferentSharedGivesDifferentKeys(t *testing.T) {
	alice := peer.ID("alice")
	bob := peer.ID("bob--")

	call1 := buildTestCall(true)
	call2 := buildTestCall(true)

	var s1, s2 [32]byte
	s1[0] = 0x01
	s2[0] = 0x02

	applyCallDHRatchet(call1, s1, alice, bob)
	applyCallDHRatchet(call2, s2, alice, bob)

	if call1.sendKey == call2.sendKey {
		t.Fatal("different shared secrets must yield different send keys")
	}
}

func TestApplyCallDHRatchet_VoiceAndVideoKeysDomainSeparated(t *testing.T) {
	// Even starting from the same value, voice and video ratchet outputs
	// must differ (different info strings: "F2F-Call-..." vs "F2F-Video-...").
	call := &CallSession{}
	// Force voice sendKey == video sendKey → see if HKDF info saves us.
	for i := range call.sendKey {
		call.sendKey[i] = 0xCC
	}
	call.recvKey = call.sendKey
	call.videoSendKey = call.sendKey
	call.videoRecvKey = call.sendKey

	var shared [32]byte
	shared[0] = 0x99
	applyCallDHRatchet(call, shared, peer.ID("a"), peer.ID("b"))

	if call.sendKey == call.videoSendKey {
		t.Fatal("voice and video keys must be domain-separated")
	}
	if call.recvKey == call.videoRecvKey {
		t.Fatal("voice and video recv keys must be domain-separated")
	}
}

func TestCallRatchetInterval_Sanity(t *testing.T) {
	if CallRatchetInterval <= 0 {
		t.Fatal("CallRatchetInterval must be positive")
	}
	// Should be noticeably longer than FS rotation to avoid thrashing,
	// but not so long it's useless for PCS.
	if CallRatchetInterval < 5*1e9 {
		t.Fatalf("CallRatchetInterval too short: %v", CallRatchetInterval)
	}
}

func TestMessageType_CallRatchetPub_Distinct(t *testing.T) {
	seen := map[MessageType]bool{}
	for _, m := range []MessageType{
		MsgTypeCallOffer, MsgTypeCallAccept, MsgTypeCallDecline, MsgTypeCallEnd,
		MsgTypeCallRatchetPub,
	} {
		if seen[m] {
			t.Fatalf("duplicate message type %d", m)
		}
		seen[m] = true
	}
}
