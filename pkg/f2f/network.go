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

func (n *Node) writeFrame(s network.Stream, data []byte) error {
	buf := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(data)))
	copy(buf[4:], data)
	_, err := s.Write(buf)
	return err
}

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

func (n *Node) InitConnect(nickname string) {
	c := n.getContactByNick(nickname)
	if c == nil {
		n.Log(LogLevelError, "Контакт '%s' не найден", nickname)
		return
	}

	c.mu.Lock()
	if c.Stream != nil {
		c.mu.Unlock()
		n.Log(LogLevelWarning, "Уже подключены к %s", nickname)
		n.EnterChat(c.PeerID)
		return
	}
	if c.Connecting {
		c.mu.Unlock()
		return
	}
	c.Connecting = true

	// Создаём контекст с возможностью отмены
	ctx, cancel := context.WithCancel(n.ctx)
	c.connectCtx = ctx
	c.connectCancel = cancel
	c.mu.Unlock()
	n.listener.OnContactUpdate()

	defer func() {
		c.mu.Lock()
		c.Connecting = false
		c.connectCtx = nil
		c.connectCancel = nil
		c.mu.Unlock()
		n.listener.OnContactUpdate()
	}()

	// Проверяем отмену перед поиском
	select {
	case <-ctx.Done():
		return
	default:
	}

	if n.host.Network().Connectedness(c.PeerID) != network.Connected {
		n.Log(LogLevelInfo, "Поиск %s...", nickname)
		ctxT, cancelT := context.WithTimeout(ctx, PeerLookupTimeout)
		defer cancelT()

		info, err := n.dht.FindPeer(ctxT, c.PeerID)
		if err == nil && len(info.Addrs) > 0 {
			n.host.Peerstore().AddAddrs(c.PeerID, info.Addrs, peerstore.PermanentAddrTTL)
		}

		// Проверяем отмену после поиска
		select {
		case <-ctx.Done():
			n.Log(LogLevelInfo, "Подключение отменено")
			return
		default:
		}
	}

	streamCtx, streamCancel := context.WithTimeout(ctx, NewStreamTimeout)
	defer streamCancel()

	s, err := n.host.NewStream(streamCtx, c.PeerID, ProtocolID)
	if err != nil {
		// Проверяем - была ли это отмена
		select {
		case <-ctx.Done():
			n.Log(LogLevelInfo, "Подключение отменено")
		default:
			n.Log(LogLevelError, "Ошибка подключения: %v", err)
		}
		return
	}

	// Ещё раз проверяем отмену после создания стрима
	select {
	case <-ctx.Done():
		s.Close()
		n.Log(LogLevelInfo, "Подключение отменено")
		return
	default:
	}

	c.mu.Lock()
	if c.Stream != nil {
		s.Close()
		c.mu.Unlock()
		n.EnterChat(c.PeerID)
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
	c.localEphPriv = ephPriv
	c.localEphPub = ephPub
	c.mu.Unlock()

	hsBytes, err := n.createHandshakeBytes(ephPub)
	if err != nil {
		n.closeStream(c)
		return
	}

	if err := n.writeFrame(s, hsBytes); err != nil {
		n.closeStream(c)
		return
	}

	c.mu.Lock()
	c.State = StatePendingOutgoing
	c.mu.Unlock()

	n.Log(LogLevelSuccess, "Отправлен запрос %s...", nickname)
	n.listener.OnContactUpdate()

	n.wg.Add(1)
	go n.readLoop(c, true)
}

func (n *Node) handleStream(s network.Stream) {
	remoteID := s.Conn().RemotePeer()
	c := n.getContactByID(remoteID)
	if c == nil {
		s.Close()
		return
	}

	c.mu.Lock()
	if c.Stream != nil {
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

	ephPriv, ephPub, err := generateEphemeralKeys()
	if err != nil {
		c.mu.Unlock()
		n.closeStream(c)
		return
	}
	c.localEphPriv = ephPriv
	c.localEphPub = ephPub
	c.mu.Unlock()
	n.listener.OnContactUpdate()

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
	hsData, err := n.readFrame(s)
	if err != nil {
		return
	}

	remoteEphPub, err := n.verifyHandshake(c, hsData)
	if err != nil {
		n.Log(LogLevelError, "Handshake fail: %v", err)
		return
	}

	c.mu.Lock()
	c.remoteEphPub = remoteEphPub
	sessionKey, err := deriveSessionKey(c.localEphPriv, c.localEphPub, remoteEphPub)
	if err != nil {
		c.mu.Unlock()
		return
	}
	c.sessionKey = sessionKey
	c.sessionEstab = true
	c.localEphPriv = nil
	c.mu.Unlock()
	n.listener.OnContactUpdate()

	if isInitiator {
		if err := n.sendSessionMessage(c, MsgTypeRequest, ""); err != nil {
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

		// Обрабатываем Cancel и Bye как сигнал завершения
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
		n.processMessage(c, msg.Type, msg.Timestamp, content)
	}
}

func (n *Node) processMessage(c *Contact, msgType string, ts int64, body string) {
	switch msgType {
	case MsgTypeRequest:
		c.mu.Lock()
		if c.State == StateActive {
			c.mu.Unlock()
			return
		}
		c.State = StatePendingIncoming
		c.mu.Unlock()
		n.Log(LogLevelWarning, "Запрос от %s! (.accept / .decline)", c.Nickname)
		n.listener.OnContactUpdate()

	case MsgTypeAccept:
		c.mu.Lock()
		// Проверяем что мы ещё ждём ответа
		if c.State != StatePendingOutgoing {
			c.mu.Unlock()
			return
		}
		c.State = StateActive
		c.mu.Unlock()
		n.Log(LogLevelSuccess, "%s принял запрос!", c.Nickname)
		n.EnterChat(c.PeerID)
		n.listener.OnContactUpdate()

	case MsgTypeDecline:
		n.closeStream(c)
		n.Log(LogLevelError, "%s отклонил запрос", c.Nickname)
		n.listener.OnContactUpdate()

	case MsgTypeText:
		c.mu.Lock()
		isActive := c.State == StateActive
		c.mu.Unlock()
		if !isActive {
			return
		}
		timestamp := time.Unix(0, ts)
		n.listener.OnMessage(c.PeerID.String(), c.Nickname, body, timestamp)
	}
}

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

	s.SetWriteDeadline(time.Now().Add(WriteTimeout))
	return n.writeFrame(s, encrypted)
}

func (n *Node) closeStream(c *Contact) {
	c.mu.Lock()
	if c.Stream != nil {
		c.Stream.Close()
		c.Stream = nil
	}
	c.State = StateIdle
	c.Connecting = false
	c.sessionKey = nil
	c.localEphPriv = nil
	c.localEphPub = nil
	c.remoteEphPub = nil
	c.sessionEstab = false

	// Отменяем контекст подключения если есть
	if c.connectCancel != nil {
		c.connectCancel()
		c.connectCancel = nil
		c.connectCtx = nil
	}
	c.mu.Unlock()

	n.listener.OnContactUpdate()
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
		n.listener.OnChatChanged("", "")
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
	n.listener.OnMessage(n.host.ID().String(), n.nickname, text, time.Now())
}
