package f2f

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"golang.org/x/crypto/chacha20poly1305"
)

// -----------------------------------------------------------------------------
// Video call: ASCII frames carried on a dedicated libp2p stream, encrypted
// with keys derived alongside the voice call's keys (deriveVideoKeys). Uses
// the same counter-based nonce scheme as voice (length-prefixed framing +
// BE counter + XChaCha20-Poly1305 ciphertext).
// -----------------------------------------------------------------------------

// StartVideoFrom begins streaming ASCII-rendered frames to the peer during
// an active voice call. The `source` argument is one of:
//
//   ""         — use whatever is configured in .settings (camera or file)
//   "camera"   — force the ffmpeg-backed webcam capture
//   "file"     — force the image/GIF stub from settings
//   <path>     — explicit file path to image/GIF
func (n *Node) StartVideoFrom(nickname, source string) error {
	c := n.getContactByNick(nickname)
	if c == nil {
		return errors.New("контакт не найден")
	}

	c.mu.Lock()
	call := c.Call
	if call == nil || call.State != CallActive {
		c.mu.Unlock()
		return errors.New("сначала нужен активный вызов (.voicecall)")
	}
	if call.videoStream != nil {
		c.mu.Unlock()
		return errors.New("видео уже идёт — ­.stopvideo чтобы остановить")
	}
	pid := c.PeerID
	c.mu.Unlock()

	// Relay-only connections can't carry video — 128 KiB cap would kill
	// both streams in seconds. Calls shouldn't even get to this point
	// on relay (initiateCallKind refuses them), but be defensive.
	if isOnRelay(n, pid) {
		return errors.New("видео недоступно через relay — нужно прямое соединение")
	}

	var src VideoSource
	var err error
	switch strings.ToLower(source) {
	case "":
		src, err = OpenDefaultVideoSource()
	case "camera", "cam", "webcam":
		s := LoadSettings()
		src, err = OpenCameraSource(s.VideoCameraID)
	case "file", "stub":
		s := LoadSettings()
		if s.VideoSourcePath == "" {
			return errors.New("файл-источник не задан в .settings")
		}
		src, err = OpenVideoSource(s.VideoSourcePath)
	case "ascii", "avatar", "logo":
		src, err = OpenAsciiAvatarSource()
	default:
		src, err = OpenVideoSource(source)
	}
	if err != nil {
		return fmt.Errorf("источник видео: %w", err)
	}

	ctx, cancel := context.WithTimeout(n.ctx, NewStreamTimeout)
	defer cancel()
	ctx = network.WithAllowLimitedConn(ctx, "f2f-video")
	s, err := n.host.NewStream(ctx, c.PeerID, VideoProtocolID)
	if err != nil {
		src.Close()
		return fmt.Errorf("видео-стрим: %w", err)
	}

	c.mu.Lock()
	if c.Call == nil || c.Call.State != CallActive {
		c.mu.Unlock()
		s.Reset()
		src.Close()
		return errors.New("вызов уже закончился")
	}
	c.Call.videoStream = s
	c.Call.videoSource = src
	c.Call.videoStopCh = make(chan struct{})
	startedCall := c.Call
	c.mu.Unlock()

	sset := LoadSettings()
	srcDesc := "(auto)"
	switch strings.ToLower(source) {
	case "":
		switch sset.VideoSourceType {
		case "camera":
			srcDesc = "camera: " + firstNonEmpty(sset.VideoCameraID, "(first dshow)")
		case "file":
			srcDesc = "file: " + sset.VideoSourcePath
		case "ascii":
			srcDesc = "ascii: (built-in avatar)"
		default:
			if sset.VideoCameraID != "" || (sset.VideoSourcePath == "" && CameraAvailable()) {
				srcDesc = "camera: " + firstNonEmpty(sset.VideoCameraID, "(first dshow)")
			} else {
				srcDesc = "file: " + sset.VideoSourcePath
			}
		}
	case "camera", "cam", "webcam":
		srcDesc = "camera: " + firstNonEmpty(sset.VideoCameraID, "(first dshow)")
	case "file", "stub":
		srcDesc = "file: " + sset.VideoSourcePath
	case "ascii":
		srcDesc = "ascii: (built-in avatar)"
	default:
		srcDesc = source
	}
	n.Log(LogLevelSuccess, "[video] Видео включено (%dx%d ASCII) — %s", VideoCols, VideoRows, srcDesc)

	startedCall.videoWG.Add(1)
	go n.videoCaptureLoop(c, startedCall, 0)
	return nil
}

// StopVideo stops the outgoing video stream (if any).
func (n *Node) StopVideo(nickname string) error {
	c := n.getContactByNick(nickname)
	if c == nil {
		return errors.New("контакт не найден")
	}
	c.mu.Lock()
	call := c.Call
	if call == nil || call.videoStream == nil {
		c.mu.Unlock()
		return errors.New("видео не идёт")
	}
	c.mu.Unlock()

	n.closeOutgoingVideo(c, "остановлено пользователем")
	return nil
}

// videoCaptureLoop drives the outgoing video: pull frame from source,
// encrypt, write to stream, sleep for the source's requested delay.
func (n *Node) videoCaptureLoop(c *Contact, call *CallSession, minFrameDelay time.Duration) {
	defer call.videoWG.Done()

	aead, err := chacha20poly1305.NewX(call.videoSendKey[:])
	if err != nil {
		n.closeOutgoingVideo(c, "aead: "+err.Error())
		return
	}

	framesSent := 0
	for {
		select {
		case <-call.videoStopCh:
			return
		case <-n.ctx.Done():
			return
		default:
		}

		frame, delay, err := call.videoSource.NextFrame()
		if err == io.EOF {
			if framesSent == 0 {
				// ffmpeg exited BEFORE giving us a single frame — camera
				// busy / not recognized / no permission. Loud log so the
				// user understands why video is black.
				n.Log(LogLevelError, "[video] источник видео завершился до первого кадра — камера занята / не опознана / нет прав")
			}
			// Post-first-frame EOF is normal shutdown (peer hangup,
			// user .stopvideo, etc). Silent — closeOutgoingVideo already
			// logs the stop reason.
			n.closeOutgoingVideo(c, "источник выдал EOF")
			return
		}
		if err != nil {
			// Check if we're in a graceful shutdown: the call may already
			// be gone (peer hung up → closeCall killed the source).
			c.mu.Lock()
			callGone := c.Call == nil || c.Call.videoSource == nil
			c.mu.Unlock()
			if callGone {
				// Don't spam the chat — the call-ended banner is plenty.
				n.closeOutgoingVideo(c, "вызов завершён")
				return
			}
			n.Log(LogLevelError, "[video] ошибка чтения кадра (отправлено %d): %v", framesSent, err)
			n.closeOutgoingVideo(c, "источник: "+err.Error())
			return
		}
		framesSent++

		ctr := atomic.AddUint64(&call.videoSendCtr, 1)

		// Advance video-send key at rotation boundaries, same scheme as voice.
		targetGen := ctr / CallKeyRotateInterval
		if targetGen > call.videoSendGen {
			keyForCounter(&call.videoSendKey, &call.videoSendGen, ctr)
			newAead, aerr := chacha20poly1305.NewX(call.videoSendKey[:])
			if aerr != nil {
				n.closeOutgoingVideo(c, "rotate aead: "+aerr.Error())
				return
			}
			aead = newAead
		}

		nonce := makeCallNonce(ctr)
		ct := aead.Seal(nil, nonce[:], []byte(frame), nil)

		c.mu.Lock()
		s := call.videoStream
		c.mu.Unlock()
		if s == nil {
			return
		}
		s.SetWriteDeadline(time.Now().Add(WriteTimeout))
		if err := writeCallFrame(s, ctr, ct); err != nil {
			n.closeOutgoingVideo(c, "запись: "+err.Error())
			return
		}

		if minFrameDelay > delay {
			delay = minFrameDelay
		}
		select {
		case <-time.After(delay):
		case <-call.videoStopCh:
			return
		case <-n.ctx.Done():
			return
		}
	}
}

// isOnRelay reports whether any of our current connections to pid is a
// circuit-v2 relay hop. Used to gate bandwidth-sensitive features so we
// don't blow the relay budget and tank the whole call.
func isOnRelay(n *Node, pid peer.ID) bool {
	for _, c := range n.host.Network().ConnsToPeer(pid) {
		if strings.Contains(c.RemoteMultiaddr().String(), "p2p-circuit") {
			return true
		}
	}
	return false
}

// firstNonEmpty returns the first non-empty string among its args, or "".
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// handleVideoStream fires when a peer opens our VideoProtocolID. We start
// a read loop that decrypts incoming frames and surfaces them to the UI via
// a listener extension (OnVideoFrame).
func (n *Node) handleVideoStream(s network.Stream) {
	remoteID := s.Conn().RemotePeer()
	c := n.getContactByID(remoteID)
	if c == nil {
		s.Reset()
		return
	}
	c.mu.Lock()
	call := c.Call
	if call == nil || call.State != CallActive {
		c.mu.Unlock()
		s.Reset()
		return
	}
	var zero [32]byte
	if call.videoRecvKey == zero {
		c.mu.Unlock()
		s.Reset()
		return
	}
	c.mu.Unlock()

	n.wg.Add(1)
	go n.videoReadLoop(c, call, s)
}

func (n *Node) videoReadLoop(c *Contact, call *CallSession, s network.Stream) {
	defer n.wg.Done()
	defer s.Close()

	aead, err := chacha20poly1305.NewX(call.videoRecvKey[:])
	if err != nil {
		return
	}

	for {
		select {
		case <-n.ctx.Done():
			return
		default:
		}

		s.SetReadDeadline(time.Now().Add(StreamReadTimeout))
		ctr, ct, err := readCallFrame(s)
		if err != nil {
			return
		}
		if ctr <= call.videoRecvCtr {
			continue
		}
		call.videoRecvCtr = ctr

		// Sync video-recv key to the sender's rotation schedule.
		targetGen := ctr / CallKeyRotateInterval
		if targetGen > call.videoRecvGen {
			keyForCounter(&call.videoRecvKey, &call.videoRecvGen, ctr)
			newAead, aerr := chacha20poly1305.NewX(call.videoRecvKey[:])
			if aerr != nil {
				return
			}
			aead = newAead
		}

		nonce := makeCallNonce(ctr)
		plain, err := aead.Open(nil, nonce[:], ct, nil)
		if err != nil {
			continue
		}

		c.mu.Lock()
		nick := c.Nickname
		c.mu.Unlock()
		n.notifyVideoFrame(c.PeerID.String(), nick, string(plain))
	}
}

func (n *Node) closeOutgoingVideo(c *Contact, reason string) {
	c.mu.Lock()
	call := c.Call
	if call == nil || call.videoStream == nil {
		c.mu.Unlock()
		return
	}
	s := call.videoStream
	src := call.videoSource
	stopCh := call.videoStopCh
	call.videoStream = nil
	call.videoSource = nil
	call.videoStopCh = nil
	nick := c.Nickname
	c.mu.Unlock()

	if stopCh != nil {
		close(stopCh)
	}
	if s != nil {
		s.Close()
	}
	if src != nil {
		_ = src.Close()
	}
	call.videoWG.Wait()
	n.Log(LogLevelInfo, "[video] Видео с %s остановлено: %s", nick, reason)
}

// notifyVideoFrame forwards a rendered frame to the listener, if it
// implements the optional VideoListener interface.
func (n *Node) notifyVideoFrame(pid, nick, frame string) {
	if vl, ok := n.listener.(VideoListener); ok {
		vl.OnVideoFrame(pid, nick, frame)
	}
}

// VideoListener is an optional interface a UIListener can implement to
// receive ASCII video frames.
type VideoListener interface {
	OnVideoFrame(peerID, nick, asciiFrame string)
}
