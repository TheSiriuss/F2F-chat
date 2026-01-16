package main

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

// --- Framing ---

// writeFrame writes length-prefixed data to stream
func (n *Node) writeFrame(s network.Stream, data []byte) error {
	buf := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(data)))
	copy(buf[4:], data)
	_, err := s.Write(buf)
	return err
}

// readFrame reads length-prefixed data from stream
func (n *Node) readFrame(s network.Stream) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(s, header); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(header)
	if length > MaxMessageSize {
		return nil, fmt.Errorf("too large: %d", length)
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(s, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// --- Connection Management ---

// InitConnect initiates connection to a contact
func (n *Node) InitConnect(nickname string) {
	c := n.getContactByNick(nickname)
	if c == nil {
		n.SafePrintf("%s Контакт '%s' не найден\n", Style.Fail, nickname)
		return
	}

	c.mu.Lock()
	if c.Stream != nil {
		c.mu.Unlock()
		n.SafePrintf("%s Уже подключены к %s\n", Style.Warning, nickname)
		n.enterChat(c.PeerID)
		return
	}
	if c.Connecting {
		c.mu.Unlock()
		n.SafePrintf("%s Подключение в процессе\n", Style.Warning)
		return
	}
	c.Connecting = true
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		c.Connecting = false
		c.mu.Unlock()
	}()

	// Find peer if not connected
	if n.host.Network().Connectedness(c.PeerID) != network.Connected {
		n.SafePrintf("%s Поиск %s...\n", Style.Searching, nickname)
		ctxT, cancel := context.WithTimeout(n.ctx, PeerLookupTimeout)
		defer cancel()

		info, err := n.dht.FindPeer(ctxT, c.PeerID)
		if err == nil && len(info.Addrs) > 0 {
			n.host.Peerstore().AddAddrs(c.PeerID, info.Addrs, peerstore.PermanentAddrTTL)
			n.SafePrintf("%s Найдено %d адресов\n", Style.OK, len(info.Addrs))
		}
	}

	// Open stream
	streamCtx, streamCancel := context.WithTimeout(n.ctx, NewStreamTimeout)
	defer streamCancel()

	s, err := n.host.NewStream(streamCtx, c.PeerID, ProtocolID)
	if err != nil {
		n.SafePrintf("%s Ошибка подключения: %v\n", Style.Fail, err)
		return
	}

	c.mu.Lock()
	if c.Stream != nil {
		s.Close()
		c.mu.Unlock()
		n.enterChat(c.PeerID)
		return
	}
	c.Stream = s
	c.Presence = PresenceOnline
	c.LastSeen = time.Now()
	c.FailCount = 0
	c.mu.Unlock()

	// Generate ephemeral keys
	ephPriv, ephPub, err := generateEphemeralKeys()
	if err != nil {
		n.SafePrintf("%s Ошибка ключей\n", Style.Fail)
		n.closeStream(c)
		return
	}

	c.mu.Lock()
	c.localEphPriv = ephPriv
	c.localEphPub = ephPub
	c.mu.Unlock()

	// Send handshake
	hsBytes, err := n.createHandshakeBytes(ephPub)
	if err != nil {
		n.SafePrintf("%s Ошибка handshake\n", Style.Fail)
		n.closeStream(c)
		return
	}

	if err := n.writeFrame(s, hsBytes); err != nil {
		n.SafePrintf("%s Ошибка отправки\n", Style.Fail)
		n.closeStream(c)
		return
	}

	c.mu.Lock()
	c.State = StatePending
	c.mu.Unlock()

	n.SafePrintf("%s Ожидание ответа...\n", Style.OK)

	n.wg.Add(1)
	go n.readLoop(c, true)
}

// handleStream handles incoming streams
func (n *Node) handleStream(s network.Stream) {
	remoteID := s.Conn().RemotePeer()
	c := n.getContactByID(remoteID)
	if c == nil {
		s.Close()
		return
	}

	c.mu.Lock()
	if c.Stream != nil {
		// Resolve conflict: lower ID keeps existing
		localID := n.host.ID()
		if localID.String() < remoteID.String() {
			c.mu.Unlock()
			s.Close()
			return
		}
		c.Stream.Close()
	}

	c.LastConnectTime = time.Now()
	c.Stream = s
	c.Presence = PresenceOnline
	c.LastSeen = time.Now()
	c.FailCount = 0
	c.mu.Unlock()

	// Generate ephemeral keys
	ephPriv, ephPub, err := generateEphemeralKeys()
	if err != nil {
		n.closeStream(c)
		return
	}

	c.mu.Lock()
	c.localEphPriv = ephPriv
	c.localEphPub = ephPub
	c.mu.Unlock()

	// Send handshake
	hsBytes, err := n.createHandshakeBytes(ephPub)
	if err != nil {
		n.closeStream(c)
		return
	}

	if err := n.writeFrame(s, hsBytes); err != nil {
		n.closeStream(c)
		return
	}

	n.wg.Add(1)
	go n.readLoop(c, false)
}

// readLoop reads messages from stream
func (n *Node) readLoop(c *Contact, isInitiator bool) {
	defer n.wg.Done()
	defer n.handleDisconnect(c, nil)

	c.mu.Lock()
	s := c.Stream
	c.mu.Unlock()

	if s == nil {
		return
	}

	// Read handshake
	s.SetReadDeadline(time.Now().Add(HandshakeTimeout))
	hsData, err := n.readFrame(s)
	if err != nil {
		return
	}

	remoteEphPub, err := n.verifyHandshake(c, hsData)
	if err != nil {
		n.SafePrintf("%s Ошибка handshake: %v\n", Style.Fail, err)
		return
	}

	// Derive session key
	c.mu.Lock()
	c.remoteEphPub = remoteEphPub

	sessionKey, err := deriveSessionKey(c.localEphPriv, c.localEphPub, remoteEphPub)
	if err != nil {
		c.mu.Unlock()
		return
	}
	c.sessionKey = sessionKey
	c.sessionEstab = true

	// Zero ephemeral private key
	for i := range c.localEphPriv {
		c.localEphPriv[i] = 0
	}
	c.localEphPriv = nil
	c.mu.Unlock()

	// Send request if initiator
	if isInitiator {
		if err := n.sendSessionMessage(c, MsgTypeRequest, ""); err != nil {
			return
		}
	}

	go n.SaveContacts()

	// Message loop
	for {
		c.mu.Lock()
		if c.Stream != s {
			c.mu.Unlock()
			return
		}
		sKey := c.sessionKey
		c.mu.Unlock()

		if sKey == nil {
			return
		}

		s.SetReadDeadline(time.Now().Add(StreamReadTimeout))
		data, err := n.readFrame(s)
		if err != nil {
			return
		}

		msg, err := n.decryptSession(data, sKey)
		if err != nil {
			continue
		}

		// Validate timestamp
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

		if msg.Type == MsgTypeBye {
			return
		}
		if msg.Type == MsgTypePing {
			continue
		}

		content := msg.Content
		if msg.Type == MsgTypeText {
			content = SanitizeInput(content, MaxMsgLength)
		}
		n.processMessage(c, msg.Type, msg.Timestamp, content)
	}
}

// processMessage handles received messages
func (n *Node) processMessage(c *Contact, msgType string, ts int64, body string) {
	switch msgType {
	case MsgTypeRequest:
		c.mu.Lock()
		if c.State == StateActive {
			c.mu.Unlock()
			return
		}
		c.State = StatePending
		c.mu.Unlock()
		n.SafePrintf("\n%s Запрос от %s! (.accept %s / .decline %s)\n",
			Style.Bell, c.Nickname, c.Nickname, c.Nickname)

	case MsgTypeAccept:
		c.mu.Lock()
		c.State = StateActive
		c.mu.Unlock()
		n.SafePrintf("\n%s %s принял!\n", Style.OK, c.Nickname)
		n.enterChat(c.PeerID)

	case MsgTypeDecline:
		n.closeStream(c)
		n.SafePrintf("\n%s %s отклонил\n", Style.Fail, c.Nickname)

	case MsgTypeText:
		c.mu.Lock()
		isActive := c.State == StateActive
		c.mu.Unlock()
		if !isActive {
			return
		}

		timestamp := time.Unix(0, ts).Format("15:04")
		n.mu.RLock()
		active := n.activeChat == c.PeerID
		n.mu.RUnlock()

		if active {
			n.SafePrintf("[%s %s]: %s\n", c.Nickname, timestamp, body)
		} else {
			n.SafePrintf("\n%s [%s %s]: %s\n", Style.Mail, c.Nickname, timestamp, body)
		}
	}
}

// sendSessionMessage sends encrypted message over session
func (n *Node) sendSessionMessage(c *Contact, msgType, body string) error {
	c.mu.Lock()
	s := c.Stream
	sKey := c.sessionKey
	c.mu.Unlock()

	if s == nil || sKey == nil {
		return errors.New("no session")
	}

	msg := &InnerMessage{
		Type:      msgType,
		Timestamp: time.Now().UnixNano(),
		Content:   body,
	}

	encrypted, err := n.encryptSession(msg, sKey)
	if err != nil {
		return err
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	c.mu.Lock()
	if c.Stream != s {
		c.mu.Unlock()
		return errors.New("stream changed")
	}
	c.mu.Unlock()

	s.SetWriteDeadline(time.Now().Add(WriteTimeout))
	return n.writeFrame(s, encrypted)
}

// closeStream closes stream and cleans up session
func (n *Node) closeStream(c *Contact) {
	c.mu.Lock()
	if c.Stream != nil {
		c.Stream.Close()
		c.Stream = nil
	}
	c.State = StateIdle
	c.Connecting = false

	// Zero sensitive data
	if c.sessionKey != nil {
		for i := range c.sessionKey {
			c.sessionKey[i] = 0
		}
		c.sessionKey = nil
	}
	if c.localEphPriv != nil {
		for i := range c.localEphPriv {
			c.localEphPriv[i] = 0
		}
		c.localEphPriv = nil
	}
	c.localEphPub = nil
	c.remoteEphPub = nil
	c.sessionEstab = false
	c.mu.Unlock()
}

// handleDisconnect handles peer disconnection
func (n *Node) handleDisconnect(c *Contact, err error) {
	c.mu.Lock()
	nick := c.Nickname
	pid := c.PeerID

	if c.Stream != nil {
		c.Stream.Close()
		c.Stream = nil
	}
	c.State = StateIdle
	c.Connecting = false

	// Zero sensitive data
	if c.sessionKey != nil {
		for i := range c.sessionKey {
			c.sessionKey[i] = 0
		}
		c.sessionKey = nil
	}
	if c.localEphPriv != nil {
		for i := range c.localEphPriv {
			c.localEphPriv[i] = 0
		}
		c.localEphPriv = nil
	}
	c.localEphPub = nil
	c.remoteEphPub = nil
	c.sessionEstab = false
	c.mu.Unlock()

	n.mu.Lock()
	wasActive := n.activeChat == pid
	if wasActive {
		n.activeChat = ""
	}
	n.mu.Unlock()

	if wasActive {
		n.updatePrompt()
		n.SafePrintf("\n%s %s отключился\n", Style.Warning, nick)
	}
}

// SendChatMessage sends a text message in active chat
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
		n.SafePrintf("%s Чат не активен\n", Style.Warning)
		return
	}

	if err := n.sendSessionMessage(c, MsgTypeText, text); err != nil {
		n.SafePrintf("%s Ошибка: %v\n", Style.Fail, err)
		return
	}
	n.SafePrintf("[Вы %s]: %s\n", time.Now().Format("15:04"), text)
}
