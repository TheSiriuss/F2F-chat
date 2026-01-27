package f2f

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
)

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

	if n.host.Network().Connectedness(pid) != network.Connected {
		n.Log(LogLevelInfo, "Поиск %s...", nickname)
		ctxT, cancelT := context.WithTimeout(ctx, PeerLookupTimeout)
		defer cancelT()

		info, err := n.dht.FindPeer(ctxT, pid)
		if err == nil && len(info.Addrs) > 0 {
			n.host.Peerstore().AddAddrs(pid, info.Addrs, peerstore.PermanentAddrTTL)
		}

		select {
		case <-ctx.Done():
			n.Log(LogLevelInfo, "Подключение отменено")
			return
		default:
		}
	}

	streamCtx, streamCancel := context.WithTimeout(ctx, NewStreamTimeout)
	defer streamCancel()

	s, err := n.host.NewStream(streamCtx, pid, ProtocolID)
	if err != nil {
		select {
		case <-ctx.Done():
			n.Log(LogLevelInfo, "Подключение отменено")
		default:
			n.Log(LogLevelError, "Ошибка подключения: %v", err)
		}
		return
	}

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
		n.closeStream(c)
		return
	}

	c.mu.Lock()
	c.State = StatePendingOutgoing
	c.mu.Unlock()

	n.Log(LogLevelSuccess, "Отправлен запрос %s...", nickname)
	n.notifyContactUpdate()

	n.wg.Add(1)
	go n.readLoop(c, true)
}

func (n *Node) handleStream(s network.Stream) {
	remoteID := s.Conn().RemotePeer()
	c := n.getContactByID(remoteID)
	if c == nil {
		s.Reset()
		return
	}

	c.mu.Lock()
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
	defer n.handleDisconnect(c, nil)

	c.mu.Lock()
	s := c.Stream
	c.mu.Unlock()

	if s == nil {
		return
	}

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
	c.handshakePriv = nil
	c.handshakePub = nil
	c.mu.Unlock()

	n.notifyContactUpdate()

	if isInitiator {
		if err := n.sendSessionMessage(c, MsgTypeRequest, nil); err != nil {
			return
		}
	}

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
