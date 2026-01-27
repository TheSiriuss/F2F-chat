package f2f

import (
	"context"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

func (n *Node) Login(nickname string) {
	// Fix #2: Валидация никнейма
	if err := n.validateNickname(nickname); err != nil {
		n.Log(LogLevelError, "Ошибка входа: %v", err)
		return
	}

	n.mu.Lock()
	n.nickname = nickname
	n.mu.Unlock()
	n.saveIdentity()
	n.Log(LogLevelSuccess, "Вы: %s", nickname)
}

func (n *Node) GetIdentityString() string {
	n.mu.RLock()
	nick := n.nickname
	n.mu.RUnlock()

	if nick == "" {
		return "Не залогинен"
	}
	// Примечание: n.naclPublic immutable после старта, читать без лока безопасно,
	// но для чистоты архитектуры можно было бы держать лок до конца.
	pubKeyB64 := base64.StdEncoding.EncodeToString(n.naclPublic[:])
	return fmt.Sprintf(".addfriend %s %s %s", nick, n.host.ID().String(), pubKeyB64)
}

func (n *Node) ConnectToBootstrap() {
	n.Log(LogLevelInfo, "Подключение к DHT...")
	var wg sync.WaitGroup
	connected := 0
	var mu sync.Mutex

	for _, addrInfo := range dht.DefaultBootstrapPeers {
		wg.Add(1)
		go func(info multiaddr.Multiaddr) {
			defer wg.Done()
			ai, err := peer.AddrInfoFromP2pAddr(info)
			if err != nil {
				return
			}
			ctx, cancel := context.WithTimeout(n.ctx, BootstrapTimeout)
			defer cancel()
			if err := n.host.Connect(ctx, *ai); err == nil {
				mu.Lock()
				connected++
				mu.Unlock()
			}
		}(addrInfo)
	}
	wg.Wait()

	if connected > 0 {
		n.Log(LogLevelSuccess, "Подключено к %d узлам", connected)
		// Fix #1: Убрали Sleep блокирующий, заменили на select
		n.wg.Add(1)
		go func() {
			defer n.wg.Done()
			select {
			case <-time.After(3 * time.Second):
				n.ForceCheckAll()
			case <-n.ctx.Done():
				return
			}
		}()
	} else {
		n.Log(LogLevelError, "Не удалось подключиться к DHT")
	}
}

func (n *Node) AddFriend(nickname, peerIDStr, pubKeyB64 string) {
	if err := n.validateNickname(nickname); err != nil {
		n.Log(LogLevelError, "Некорректный ник: %v", err)
		return
	}

	peerID, err := peer.Decode(peerIDStr)
	if err != nil {
		n.Log(LogLevelError, "Ошибка PeerID")
		return
	}
	if peerID == n.host.ID() {
		n.Log(LogLevelError, "Нельзя добавить себя")
		return
	}

	pubBytes, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil || len(pubBytes) != 32 {
		n.Log(LogLevelError, "Ошибка ключа")
		return
	}
	var pubKey [32]byte
	copy(pubKey[:], pubBytes)

	n.mu.Lock()
	if _, exists := n.nickMap[nickname]; exists {
		n.mu.Unlock()
		n.Log(LogLevelError, "Ник '%s' занят", nickname)
		return
	}
	contact := &Contact{
		Nickname:   nickname,
		PeerID:     peerID,
		PublicKey:  pubKey,
		SeenNonces: make(map[int64]time.Time),
		State:      StateIdle,
		Presence:   PresenceUnknown,
	}
	n.contacts[peerID] = contact
	n.nickMap[nickname] = peerID
	n.mu.Unlock()

	n.Log(LogLevelSuccess, "Добавлен: %s", nickname)
	n.SaveContacts()
	// Fix #6: Safe listener
	n.notifyContactUpdate()

	// Fix #3: Предотвращение утечки горутины
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		n.FindContact(nickname)
	}()
}

func (n *Node) HandleDecision(nick string, accept bool) {
	c := n.getContactByNick(nick)
	if c == nil {
		n.Log(LogLevelError, "Контакт '%s' не найден", nick)
		return
	}

	c.mu.Lock()
	isIncoming := c.State == StatePendingIncoming
	hasSession := c.sessionEstab
	pid := c.PeerID
	c.mu.Unlock()

	if !isIncoming || !hasSession {
		n.Log(LogLevelWarning, "Нет входящего запроса от %s", nick)
		return
	}

	if accept {
		if err := n.sendSessionMessage(c, MsgTypeAccept, "OK"); err != nil {
			n.Log(LogLevelError, "Ошибка отправки подтверждения: %v", err)
			return
		}
		c.mu.Lock()
		c.State = StateActive
		c.mu.Unlock()
		// Fix #6
		n.notifyContactUpdate()
		n.EnterChat(pid)
	} else {
		// Fix #4, #5: Используем helper для отправки отказа и закрытия
		n.sendTerminalMessage(c, MsgTypeDecline, "NO")
		n.Log(LogLevelSuccess, "Отклонено")
		// Fix #6
		n.notifyContactUpdate()
	}
}

func (n *Node) Disconnect(nick string) {
	c := n.getContactByNick(nick)
	if c == nil {
		n.Log(LogLevelError, "Контакт '%s' не найден", nick)
		return
	}

	c.mu.Lock()
	state := c.State
	hasStream := c.Stream != nil
	hasSession := c.sessionEstab
	isConnecting := c.Connecting
	cancelFunc := c.connectCancel
	pid := c.PeerID
	c.mu.Unlock()

	if state == StateIdle && !isConnecting && !hasStream {
		n.Log(LogLevelWarning, "Нет активного соединения с %s", nick)
		return
	}

	if cancelFunc != nil {
		cancelFunc()
	}

	n.mu.Lock()
	wasActiveChat := n.activeChat == pid
	if wasActiveChat {
		n.activeChat = ""
	}
	n.mu.Unlock()

	if wasActiveChat {
		// Fix #6
		n.notifyChatChanged("", "")
	}

	// Fix #4, #5: Централизованная логика завершения
	if hasStream && hasSession {
		var msgType MessageType
		switch state {
		case StatePendingOutgoing:
			msgType = MsgTypeCancel
		case StatePendingIncoming:
			msgType = MsgTypeDecline
		case StateActive:
			msgType = MsgTypeBye
		default:
			msgType = MsgTypeBye
		}
		// Отправляет сообщение, ждет (немного) и закрывает стрим
		n.sendTerminalMessage(c, msgType, nil)
	} else {
		n.closeStream(c)
	}

	switch state {
	case StatePendingOutgoing:
		n.Log(LogLevelSuccess, "Запрос к %s отменён", nick)
	case StatePendingIncoming:
		n.Log(LogLevelSuccess, "Входящий запрос от %s отклонён", nick)
	case StateActive:
		n.Log(LogLevelSuccess, "Чат с %s завершён", nick)
	default:
		if isConnecting {
			n.Log(LogLevelSuccess, "Подключение к %s отменено", nick)
		} else {
			n.Log(LogLevelSuccess, "Соединение с %s разорвано", nick)
		}
	}

	// Fix #6
	n.notifyContactUpdate()
}

func (n *Node) DisconnectByPeerID(pid peer.ID) {
	c := n.getContactByID(pid)
	if c == nil {
		return
	}
	c.mu.Lock()
	nick := c.Nickname
	c.mu.Unlock()
	n.Disconnect(nick)
}

func (n *Node) EnterChat(id peer.ID) {
	n.mu.Lock()
	c := n.contacts[id]
	if c == nil {
		n.mu.Unlock()
		return
	}
	n.activeChat = id
	n.mu.Unlock()

	c.mu.Lock()
	nick := c.Nickname
	c.mu.Unlock()

	// Fix #6
	n.notifyChatChanged(id.String(), nick)
	n.Log(LogLevelInfo, "ЧАТ: %s (Forward Secrecy: ON, XChaCha20)", nick)
}

func (n *Node) LeaveChat() {
	n.mu.Lock()
	id := n.activeChat
	n.activeChat = ""
	n.mu.Unlock()

	// Fix #6
	n.notifyChatChanged("", "")

	if id == "" {
		return
	}

	c := n.getContactByID(id)
	if c != nil {
		// Fix #4, #5: Terminal message
		n.sendTerminalMessage(c, MsgTypeBye, nil)
		n.Log(LogLevelSuccess, "Чат завершён")
		// Fix #6
		n.notifyContactUpdate()
	}
}

func (n *Node) Logout() {
	n.mu.Lock()
	// Копируем слайс контактов под локом (Snapshotting)
	// Это безопасно (см. пункт 7 ревью)
	contacts := make([]*Contact, 0, len(n.contacts))
	for _, c := range n.contacts {
		contacts = append(contacts, c)
	}
	oldNick := n.nickname
	n.activeChat = ""
	n.nickname = ""
	n.mu.Unlock()

	if oldNick == "" {
		n.Log(LogLevelWarning, "Вы не залогинены")
		return
	}

	for _, c := range contacts {
		// Fix #4: Использование terminal message для каждого контакта
		// Внутри проверяется наличие сессии
		n.sendTerminalMessage(c, MsgTypeBye, nil)
	}

	n.saveIdentity()

	// Fix #6
	n.notifyChatChanged("", "")
	n.notifyContactUpdate()
	n.Log(LogLevelSuccess, "Вы вышли из аккаунта")
}

func (n *Node) RemoveFriend(nick string) {
	c := n.getContactByNick(nick)
	if c == nil {
		n.Log(LogLevelError, "Контакт '%s' не найден", nick)
		return
	}

	c.mu.Lock()
	pid := c.PeerID
	c.mu.Unlock()

	// Fix #4: Отправляем Bye и закрываем
	n.sendTerminalMessage(c, MsgTypeBye, nil)

	n.mu.Lock()
	wasActiveChat := n.activeChat == pid
	if wasActiveChat {
		n.activeChat = ""
	}
	delete(n.contacts, pid)
	delete(n.nickMap, nick)
	n.mu.Unlock()

	if wasActiveChat {
		// Fix #6
		n.notifyChatChanged("", "")
	}

	n.SaveContacts()
	// Fix #6
	n.notifyContactUpdate()
	n.Log(LogLevelSuccess, "Контакт '%s' удалён", nick)
}

func (n *Node) IsLoggedIn() bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.nickname != ""
}
