package f2f

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
)

// reportConnType logs which kind of transport we ended up on — direct TCP/QUIC
// vs. a relay circuit. Users who hit "Канал не открылся" over relay connections
// can often fix it by retrying or by running a local relay themselves.
func reportConnType(n *Node, pid peer.ID, nickname string) {
	conns := n.host.Network().ConnsToPeer(pid)
	if len(conns) == 0 {
		return
	}
	seenRelay := false
	seenDirect := false
	for _, conn := range conns {
		if strings.Contains(conn.RemoteMultiaddr().String(), "p2p-circuit") {
			seenRelay = true
		} else {
			seenDirect = true
		}
	}
	switch {
	case seenDirect && seenRelay:
		n.Log(LogLevelInfo, "Связь: прямое соединение + relay")
	case seenDirect:
		n.Log(LogLevelInfo, "Связь: прямое соединение [OK]")
	case seenRelay:
		n.Log(LogLevelWarning, "Связь: через relay — потоки могут быть медленными/рубиться")
	}
}

// openChatStreamWithRetry opens the chat protocol stream with up to 3
// attempts.
//
// Two critical things here:
//
//  1. network.WithAllowLimitedConn — libp2p circuit-v2 relays mark the
//     transport connection as "limited" (bandwidth + time caps). Opening
//     a sub-protocol stream over a limited conn is REFUSED by default,
//     which is the #1 cause of "failed to open stream: context deadline
//     exceeded" on NAT-restricted peers. We explicitly opt-in so the
//     stream works even over relay — hole-punching (if it succeeds) will
//     upgrade it to direct mid-session.
//
//  2. We DON'T kill existing connections between attempts on the first
//     retry — that would break any in-flight hole-punch attempt that's
//     trying to upgrade the relay path to a direct one. Only on the
//     last-resort retry do we force a re-dial.
func (n *Node) openChatStreamWithRetry(parent context.Context, pid peer.ID, nickname string) (network.Stream, error) {
	// Per-attempt budget escalates: first try quick (connection may be
	// healthy), then give hole-puncher more time, then a final full dial.
	perAttempt := []time.Duration{20 * time.Second, 25 * time.Second, 30 * time.Second}
	const maxAttempts = 3

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		n.Log(LogLevelInfo, "Открытие канала /f2f-chat/1.4.0 (попытка %d/%d, %s)...",
			attempt, maxAttempts, perAttempt[attempt-1])

		ctx, cancel := context.WithTimeout(parent, perAttempt[attempt-1])
		// Permit sub-protocol streams over relay (circuit-v2 limited conns).
		// Without this, NewStream refuses relay connections and times out.
		ctx = network.WithAllowLimitedConn(ctx, "f2f-chat")
		s, err := n.host.NewStream(ctx, pid, ProtocolID)
		cancel()
		if err == nil {
			return s, nil
		}

		select {
		case <-parent.Done():
			n.Log(LogLevelInfo, "Подключение отменено")
			return nil, parent.Err()
		default:
		}

		if attempt == maxAttempts {
			c := n.getContactByNick(nickname)
			if c != nil {
				c.mu.Lock()
				c.LastConnectFailAt = time.Now()
				c.mu.Unlock()
			}
			n.Log(LogLevelError,
				"Канал не открылся за %d попытки — relay не форвардит и hole punch не прошёл: %v",
				maxAttempts, err)
			return nil, err
		}

		// On attempts 1→2 don't tear down the connection — hole puncher
		// may still be working on upgrading it to direct. On 2→3 force a
		// re-dial as last resort.
		if attempt >= 2 {
			n.Log(LogLevelWarning, "Попытка %d провалилась (%v) — закрываю соединение и пробую снова...", attempt, err)
			for _, conn := range n.host.Network().ConnsToPeer(pid) {
				_ = conn.Close()
			}
			time.Sleep(750 * time.Millisecond)

			connCtx, connCancel := context.WithTimeout(parent, 15*time.Second)
			addrs := n.host.Peerstore().Addrs(pid)
			if err := n.host.Connect(connCtx, peer.AddrInfo{ID: pid, Addrs: addrs}); err != nil {
				connCancel()
				n.Log(LogLevelWarning, "Повторное подключение не удалось: %v", err)
				continue
			}
			connCancel()
			reportConnType(n, pid, nickname)
		} else {
			n.Log(LogLevelWarning, "Попытка %d провалилась (%v) — жду hole punch 2с и пробую снова...", attempt, err)
			// Hole puncher runs in background; give it a beat.
			select {
			case <-time.After(2 * time.Second):
			case <-parent.Done():
				return nil, parent.Err()
			}
		}
	}
	return nil, errors.New("все попытки исчерпаны")
}

// writeFrame пишет фрейм с типом
func (n *Node) writeFrame(s network.Stream, frameType byte, data []byte) error {
	totalLen := 1 + len(data)
	buf := make([]byte, 4+totalLen)
	binary.BigEndian.PutUint32(buf[:4], uint32(totalLen))
	buf[4] = frameType
	copy(buf[5:], data)
	_, err := s.Write(buf)
	return err
}

func (n *Node) writeMsgFrame(s network.Stream, data []byte) error {
	return n.writeFrame(s, FrameTypeMsg, data)
}

func (n *Node) writeBinaryFrame(s network.Stream, data []byte) error {
	return n.writeFrame(s, FrameTypeBinary, data)
}

func (n *Node) readFrame(s network.Stream) (byte, []byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(s, header); err != nil {
		return 0, nil, err
	}
	length := binary.BigEndian.Uint32(header)
	if length > MaxFrameSize {
		return 0, nil, fmt.Errorf("frame too large: %d", length)
	}
	if length < 1 {
		return 0, nil, errors.New("frame too small")
	}

	buf := make([]byte, length)
	if _, err := io.ReadFull(s, buf); err != nil {
		return 0, nil, err
	}

	frameType := buf[0]
	data := buf[1:]
	return frameType, data, nil
}

func (n *Node) readMsgFrame(s network.Stream) ([]byte, error) {
	frameType, data, err := n.readFrame(s)
	if err != nil {
		return nil, err
	}
	if frameType != FrameTypeMsg {
		return nil, errors.New("expected Msg frame")
	}
	return data, nil
}

func (n *Node) InitConnect(nickname string) {
	c := n.getContactByNick(nickname)
	if c == nil {
		n.Log(LogLevelError, "Контакт '%s' не найден", nickname)
		return
	}

	c.mu.Lock()
	if c.Stream != nil {
		state := c.State
		pid := c.PeerID
		c.mu.Unlock()
		n.Log(LogLevelWarning, "Уже подключены к %s", nickname)
		// Входим в чат только если он уже активен
		if state == StateActive {
			n.EnterChat(pid)
		}
		return
	}
	if c.Connecting {
		c.mu.Unlock()
		return
	}
	c.Connecting = true

	ctx, cancel := context.WithCancel(n.ctx)
	c.connectCtx = ctx
	c.connectCancel = cancel
	pid := c.PeerID
	c.mu.Unlock()

	n.notifyContactUpdate()

	defer func() {
		c.mu.Lock()
		c.Connecting = false
		c.connectCtx = nil
		c.connectCancel = nil
		c.mu.Unlock()
		n.notifyContactUpdate()
	}()

	select {
	case <-ctx.Done():
		return
	default:
	}

	if conn := n.host.Network().Connectedness(pid); conn != network.Connected && conn != network.Limited {
		// DO NOT ClearAddrs — libp2p's peerstore is the runtime cache of
		// addresses learned via identify / previous sessions / presence
		// loop, and it's already TTL-managed. Wiping it nukes perfectly
		// good addrs and leaves us at the mercy of DHT freshness.
		existing := n.host.Peerstore().Addrs(pid)

		// Always ask DHT for fresh addrs, but TREAT IT AS AUGMENTATION —
		// merge with what's already there. 0 addrs from DHT doesn't mean
		// we're out of luck if peerstore already knows routes.
		n.Log(LogLevelInfo, "Поиск %s в DHT (у peerstore %d адрес(ов))...", nickname, len(existing))
		ctxT, cancelT := context.WithTimeout(ctx, PeerLookupTimeout)
		info, err := n.dht.FindPeer(ctxT, pid)
		cancelT()
		if err != nil {
			n.Log(LogLevelWarning, "DHT: %v — пробую адреса из peerstore", err)
		} else if len(info.Addrs) > 0 {
			n.host.Peerstore().AddAddrs(pid, info.Addrs, peerstore.AddressTTL)
			n.Log(LogLevelInfo, "DHT добавил %d адрес(ов) %s", len(info.Addrs), nickname)
		} else {
			n.Log(LogLevelWarning, "DHT вернул 0 адресов — использую только peerstore (%d)", len(existing))
		}

		select {
		case <-ctx.Done():
			n.Log(LogLevelInfo, "Подключение отменено")
			return
		default:
		}
	}

	// Show exactly what we have before attempting the stream — this tells
	// the user whether the subsequent timeout is about address reachability,
	// NAT traversal, or protocol negotiation.
	addrs := n.host.Peerstore().Addrs(pid)
	if len(addrs) == 0 {
		n.Log(LogLevelError, "Нет известных адресов %s — .bootstrap и подождите, пока DHT подтянется", nickname)
		return
	}

	// Step 1: establish any transport connection. This separates "can't
	// reach peer at all" (NAT/firewall) from "reached peer but protocol
	// negotiation failed" (version mismatch / code bug).
	if conn := n.host.Network().Connectedness(pid); conn != network.Connected && conn != network.Limited {
		connCtx, connCancel := context.WithTimeout(ctx, NewStreamTimeout)
		if err := n.host.Connect(connCtx, peer.AddrInfo{ID: pid, Addrs: addrs}); err != nil {
			connCancel()
			n.Log(LogLevelError,
				"Не удалось дозвониться до %s (%d адрес(ов) — NAT/firewall?): %v",
				nickname, len(addrs), err)
			return
		}
		connCancel()
		n.Log(LogLevelInfo, "[link] Транспорт с %s установлен", nickname)
	}

	// Diagnostic: tell the user whether we're on a direct or relay connection.
	// Relay circuits (p2p-circuit) are frequently slow/flaky — if NewStream
	// hangs over one, retrying may pick up a direct path after hole-punching.
	reportConnType(n, pid, nickname)

	// Step 2: open our chat protocol stream with retries. Relay-only initial
	// connections sometimes can't forward sub-protocols; closing and retrying
	// lets libp2p's hole-puncher try for a direct path.
	s, err := n.openChatStreamWithRetry(ctx, pid, nickname)
	if err != nil {
		return
	}
	n.Log(LogLevelInfo, "Канал открыт, отправляю handshake...")

	c.mu.Lock()
	if c.Stream != nil {
		c.mu.Unlock()
		s.Reset()
		n.EnterChat(pid)
		return
	}
	c.Stream = s
	c.Presence = PresenceOnline
	c.LastSeen = time.Now()
	c.FailCount = 0

	ephPriv, ephPub, err := generateEphemeralKeys()
	if err != nil {
		c.mu.Unlock()
		n.closeStream(c)
		return
	}
	c.handshakePriv = ephPriv
	c.handshakePub = ephPub
	c.mu.Unlock()

	hsBytes, err := n.createHandshakeBytes(ephPub)
	if err != nil {
		n.closeStream(c)
		return
	}

	if err := n.writeMsgFrame(s, hsBytes); err != nil {
		n.Log(LogLevelError, "Не смог отправить handshake: %v", err)
		n.closeStream(c)
		return
	}

	c.mu.Lock()
	c.State = StatePendingOutgoing
	c.mu.Unlock()

	n.Log(LogLevelSuccess, "Handshake отправлен %s — жду ответ...", nickname)
	n.notifyContactUpdate()

	n.wg.Add(1)
	go n.readLoop(c, true)
}

func (n *Node) handleStream(s network.Stream) {
	remoteID := s.Conn().RemotePeer()
	c := n.getContactByID(remoteID)
	if c == nil {
		// Unknown peer opened a stream — this is the #1 silent-failure
		// cause of "connect works on one side but nothing on the other".
		// Explicitly log so the user realises the other side hasn't added
		// them as a contact.
		n.Log(LogLevelWarning,
			"Входящий стрим от неизвестного peer'а %s — он вас ещё не добавил в контакты?",
			remoteID.String())
		s.Reset()
		return
	}
	n.Log(LogLevelInfo, "Входящий канал от %s, handshake...", c.Nickname)

	c.mu.Lock()
	// Tie-break when both sides happen to dial each other at once: the one
	// with the numerically-smaller peerID backs off. libp2p already
	// authenticates the remote peerID at transport level, so we don't need
	// an explicit cooldown here — it was found to delay legitimate
	// reconnects after hole-punching retries.
	if c.Stream != nil {
		localID := n.host.ID()
		if localID.String() < remoteID.String() {
			c.mu.Unlock()
			s.Reset()
			return
		}
		c.Stream.Reset()
	}

	c.LastConnectTime = time.Now()
	c.Stream = s
	c.Presence = PresenceOnline
	c.LastSeen = time.Now()
	c.FailCount = 0

	ephPriv, ephPub, err := generateEphemeralKeys()
	if err != nil {
		c.mu.Unlock()
		n.closeStream(c)
		return
	}
	c.handshakePriv = ephPriv
	c.handshakePub = ephPub
	c.mu.Unlock()

	n.notifyContactUpdate()

	hsBytes, err := n.createHandshakeBytes(ephPub)
	if err != nil {
		n.closeStream(c)
		return
	}

	if err := n.writeMsgFrame(s, hsBytes); err != nil {
		n.closeStream(c)
		return
	}

	n.wg.Add(1)
	go n.readLoop(c, false)
}

func (n *Node) readLoop(c *Contact, isInitiator bool) {
	defer n.wg.Done()

	c.mu.Lock()
	s := c.Stream
	c.mu.Unlock()

	if s == nil {
		return
	}

	// Ownership guard: if the simultaneous-dial tie-break in handleStream
	// swaps c.Stream from under us (our outgoing stream was the "losing"
	// one), we must NOT call handleDisconnect — it would close the
	// replacement stream that the winning side is busy establishing.
	// Only close down if we're still the active stream when the loop exits.
	defer func() {
		c.mu.Lock()
		current := c.Stream
		c.mu.Unlock()
		if current != s {
			return
		}
		n.handleDisconnect(c, nil)
	}()

	s.SetReadDeadline(time.Now().Add(HandshakeTimeout))
	hsData, err := n.readMsgFrame(s)
	if err != nil {
		return
	}

	remoteEphPub, err := n.verifyHandshake(c, hsData)
	if err != nil {
		n.Log(LogLevelError, "Handshake fail: %v", err)
		return
	}

	c.mu.Lock()
	initShared, err := deriveSessionKey(c.handshakePriv, c.handshakePub, remoteEphPub)
	if err != nil {
		c.mu.Unlock()
		return
	}

	// ВАЖНО: Сохраняем handshake ключи ДО инициализации Ratchet
	handshakePriv := c.handshakePriv
	handshakePub := c.handshakePub

	// Для initiator передаем remote pub, для responder - nil
	var remotePubForRatchet *[32]byte
	if isInitiator {
		remotePubForRatchet = remoteEphPub
	}

	// Инициализируем Ratchet с правильными параметрами
	ratchet, err := InitializeRatchet(initShared, remotePubForRatchet, handshakePriv, handshakePub, isInitiator)
	if err != nil {
		c.mu.Unlock()
		return
	}

	c.Ratchet = ratchet
	c.sessionEstab = true
	// Compute SAS while both handshake ephemerals are still available.
	c.SASCode = ComputeSAS(handshakePub[:], remoteEphPub[:])
	c.handshakePriv = nil
	c.handshakePub = nil
	c.mu.Unlock()

	n.notifyContactUpdate()

	if isInitiator {
		if err := n.sendSessionMessage(c, MsgTypeRequest, nil); err != nil {
			return
		}
	}

	// Address cache intentionally disabled — .connect always goes through
	// DHT for a fresh lookup. Cached addresses from previous sessions were
	// a reliability hazard (stale LAN IPs / NAT ports / dead relays).

	go n.SaveContacts()

	for {
		c.mu.Lock()
		if c.Stream != s {
			c.mu.Unlock()
			return
		}
		if c.Ratchet == nil {
			c.mu.Unlock()
			return
		}
		c.mu.Unlock()

		s.SetReadDeadline(time.Now().Add(StreamReadTimeout))
		frameType, data, err := n.readFrame(s)
		if err != nil {
			return
		}

		// Double Ratchet Decryption
		if len(data) < 40 {
			continue // Junk
		}

		headerBytes := data[:40]
		ciphertext := data[40:]

		c.mu.Lock()
		plaintext, err := n.RatchetDecrypt(c.Ratchet, headerBytes, ciphertext)
		c.mu.Unlock()

		if err != nil {
			n.Log(LogLevelError, "Decryption error from %s: %v", c.Nickname, err)
			continue
		}

		if frameType == FrameTypeBinary {
			// Передаем расшифрованные данные в file_transfer.go
			n.processBinaryChunk(c, plaintext)
			continue
		}

		msg := &InnerMessage{}
		if err := msg.Unmarshal(plaintext); err != nil {
			continue
		}

		now := time.Now().UnixNano()
		if msg.Timestamp > now+int64(MaxTimeSkew) {
			continue
		}

		c.mu.Lock()
		if msg.Timestamp <= c.LastMsgTime {
			c.mu.Unlock()
			continue
		}
		c.LastMsgTime = msg.Timestamp
		c.mu.Unlock()

		if msg.Type == MsgTypeBye || msg.Type == MsgTypeCancel {
			if msg.Type == MsgTypeCancel {
				n.Log(LogLevelInfo, "%s отменил запрос", c.Nickname)
			}
			return
		}
		if msg.Type == MsgTypePing {
			continue
		}

		content := msg.Content
		if msg.Type == MsgTypeText {
			content = SanitizeInput(content, MaxMsgLength)
		}
		n.processMessage(c, msg.Type, msg.Timestamp, content, msg.Payload)
	}
}

func (n *Node) processMessage(c *Contact, msgType MessageType, ts int64, content string, payload []byte) {
	c.mu.Lock()
	nick := c.Nickname
	pid := c.PeerID
	state := c.State
	c.mu.Unlock()

	switch msgType {
	case MsgTypeRequest:
		if state == StateActive {
			return
		}
		c.mu.Lock()
		c.State = StatePendingIncoming
		c.mu.Unlock()
		n.Log(LogLevelWarning, "Запрос от %s! (.accept / .decline)", nick)
		n.notifyContactUpdate()

	case MsgTypeAccept:
		if state != StatePendingOutgoing {
			return
		}
		c.mu.Lock()
		c.State = StateActive
		c.mu.Unlock()
		n.Log(LogLevelSuccess, "%s принял запрос!", nick)
		n.EnterChat(pid)
		n.notifyContactUpdate()

	case MsgTypeDecline:
		n.closeStream(c)
		n.Log(LogLevelError, "%s отклонил запрос", nick)
		n.notifyContactUpdate()

	case MsgTypeText:
		if state != StateActive {
			return
		}
		timestamp := time.Unix(0, ts)
		n.notifyMessage(pid.String(), nick, content, timestamp)

	case MsgTypeFileOffer:
		n.processFileOffer(c, payload)
	case MsgTypeFileAccept:
		n.processFileAccept(c, payload)
	case MsgTypeFileDecline:
		n.processFileDecline(c, payload)
	case MsgTypeFileCancel:
		n.processFileCancel(c, payload)
	case MsgTypeFileDone:
		n.processFileDone(c, payload)

	// MsgTypeCall* are no longer used — calls have their own libp2p
	// protocol (AudioProtocolID) with in-band signaling, independent of
	// chat. If one arrives from an older client, silently drop.
	case MsgTypeCallOffer, MsgTypeCallAccept, MsgTypeCallDecline, MsgTypeCallEnd, MsgTypeCallRatchetPub:
		// no-op
	}
}

func (n *Node) sendSessionMessage(c *Contact, msgType MessageType, content any) error {
	c.mu.Lock()
	s := c.Stream
	ratchet := c.Ratchet
	c.mu.Unlock()

	if s == nil || ratchet == nil {
		return errors.New("no session")
	}

	msg := &InnerMessage{
		Type:      msgType,
		Timestamp: time.Now().UnixNano(),
	}

	if content != nil {
		switch v := content.(type) {
		case string:
			msg.Content = v
		case []byte:
			msg.Payload = v
		}
	}

	plaintext := msg.Marshal()

	c.mu.Lock()
	headerBytes, ciphertext, err := n.RatchetEncrypt(c.Ratchet, plaintext)
	c.mu.Unlock()

	if err != nil {
		return err
	}

	packet := make([]byte, len(headerBytes)+len(ciphertext))
	copy(packet[0:], headerBytes)
	copy(packet[len(headerBytes):], ciphertext)

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	s.SetWriteDeadline(time.Now().Add(WriteTimeout))
	return n.writeMsgFrame(s, packet)
}

// FIX: Удален лишний аргумент sessionKey
func (n *Node) sendBinaryChunk(c *Contact, fileID [16]byte, index, total uint32, data []byte) error {
	c.mu.Lock()
	s := c.Stream
	ratchet := c.Ratchet
	c.mu.Unlock()

	if s == nil || ratchet == nil {
		return errors.New("no stream")
	}

	packetInner := make([]byte, BinaryChunkHeaderSize+len(data))
	copy(packetInner[0:16], fileID[:])
	binary.BigEndian.PutUint32(packetInner[16:20], index)
	binary.BigEndian.PutUint32(packetInner[20:24], total)
	copy(packetInner[24:], data)

	c.mu.Lock()
	headerBytes, ciphertext, err := n.RatchetEncrypt(c.Ratchet, packetInner)
	c.mu.Unlock()

	if err != nil {
		return err
	}

	packet := make([]byte, len(headerBytes)+len(ciphertext))
	copy(packet[0:], headerBytes)
	copy(packet[len(headerBytes):], ciphertext)

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	s.SetWriteDeadline(time.Now().Add(WriteTimeout))
	return n.writeBinaryFrame(s, packet)
}

func (n *Node) closeStream(c *Contact) {
	c.mu.Lock()
	if c.Stream != nil {
		c.Stream.Close()
		c.Stream.Reset()
		c.Stream = nil
	}

	c.Ratchet = nil
	c.State = StateIdle
	c.Connecting = false
	c.sessionEstab = false
	c.SASCode = ""
	c.PendingFile = nil

	if c.connectCancel != nil {
		c.connectCancel()
		c.connectCancel = nil
		c.connectCtx = nil
	}
	c.mu.Unlock()

	n.notifyContactUpdate()
}

func (n *Node) handleDisconnect(c *Contact, err error) {
	c.mu.Lock()
	nick := c.Nickname
	pid := c.PeerID
	c.mu.Unlock()

	n.closeStream(c)

	n.mu.Lock()
	wasActive := n.activeChat == pid
	if wasActive {
		n.activeChat = ""
	}
	n.mu.Unlock()

	if wasActive {
		n.notifyChatChanged("", "")
		n.Log(LogLevelWarning, "%s отключился", nick)
	}
}

func (n *Node) SendChatMessage(peerID peer.ID, text string) {
	c := n.getContactByID(peerID)
	if c == nil {
		n.LeaveChat()
		return
	}

	c.mu.Lock()
	state := c.State
	c.mu.Unlock()

	if state != StateActive {
		n.Log(LogLevelWarning, "Чат не активен")
		return
	}

	if err := n.sendSessionMessage(c, MsgTypeText, text); err != nil {
		n.Log(LogLevelError, "Ошибка отправки: %v", err)
		return
	}

	n.mu.RLock()
	myNick := n.nickname
	n.mu.RUnlock()

	n.notifyMessage(n.host.ID().String(), myNick, text, time.Now())
}

func (n *Node) sendTerminalMessage(c *Contact, msgType MessageType, content any) {
	c.mu.Lock()
	hasStream := c.Stream != nil
	hasSession := c.sessionEstab
	c.mu.Unlock()

	if hasStream && hasSession {
		if err := n.sendSessionMessage(c, msgType, content); err != nil {
			// Ignore
		}
		select {
		case <-time.After(100 * time.Millisecond):
		case <-n.ctx.Done():
		}
	}
	n.closeStream(c)
}
