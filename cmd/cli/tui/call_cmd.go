package tui

import (
	tea "github.com/charmbracelet/bubbletea"

	"github.com/TheSiriuss/aski/pkg/aski"
)

// -----------------------------------------------------------------------------
// .call / .vidcall — now fully independent of chat. The call protocol uses
// its own libp2p stream (AudioProtocolID) with in-band signaling (Offer /
// Accept / Decline frames) — no chat handshake required. If the peer isn't
// in our existing libp2p connection set, call.go handles DHT lookup + dial
// transparently before sending the Offer.
// -----------------------------------------------------------------------------

// voiceCall fires a voice-only call.
func voiceCall(node *f2f.Node, nick string) tea.Cmd {
	return func() tea.Msg {
		if err := node.InitiateCall(nick); err != nil {
			return MsgLog{Level: f2f.LogLevelError, Format: "Не удалось начать вызов: " + err.Error()}
		}
		return nil
	}
}

// videoCall fires a video call. Video capture auto-starts on BOTH sides
// when the call activates (see awaitCallResponse on the caller side and
// handleAudioStream on the callee side — both call StartVideoFrom once
// shared keys are derived and beginCall returns). Pre-flight check here
// just gives the user an immediate error if video source is unavailable.
func videoCall(node *f2f.Node, nick string) tea.Cmd {
	return func() tea.Msg {
		if err := preflightVideo(); err != nil {
			return MsgLog{Level: f2f.LogLevelError, Format: "Видеовызов невозможен: " + err.Error()}
		}
		if err := node.InitiateVideoCall(nick); err != nil {
			return MsgLog{Level: f2f.LogLevelError, Format: "Не удалось начать видеовызов: " + err.Error()}
		}
		return nil
	}
}

// preflightVideo validates that we have SOMETHING to send as video before
// we kick off the call. Returns a user-readable error if nothing works.
func preflightVideo() error {
	src, err := f2f.OpenDefaultVideoSource()
	if err != nil {
		return err
	}
	src.Close()
	return nil
}
