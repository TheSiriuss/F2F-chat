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
	n.mu.Lock()
	n.nickname = nickname
	n.mu.Unlock()
	n.saveIdentity()
	n.Log(LogLevelSuccess, "Вы: %s", nickname)
}

func (n *Node) GetIdentityString() string {
	if n.nickname == "" {
		return "Не залогинен"
	}
	pubKeyB64 := base64.StdEncoding.EncodeToString(n.naclPublic[:])
	return fmt.Sprintf(".addfriend %s %s %s", n.nickname, n.host.ID().String(), pubKeyB64)
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
		go func() {
			time.Sleep(3 * time.Second)
			n.ForceCheckAll()
		}()
	} else {
		n.Log(LogLevelError, "Не удалось подключиться к DHT")
	}
}

func (n *Node) AddFriend(nickname, peerIDStr, pubKeyB64 string) {
	if nickname == "" {
		n.Log(LogLevelError, "Пустой ник")
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
	n.listener.OnContactUpdate()

	go n.FindContact(nickname)
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
	c.mu.Unlock()

	if !isIncoming || !hasSession {
		n.Log(LogLevelWarning, "Нет входящего запроса от %s", nick)
		return
	}

	if accept {
		if err := n.sendSessionMessage(c, MsgTypeAccept, "OK"); err != nil {
			n.Log(LogLevelError, "Ошибка: %v", err)
			return
		}
		c.mu.Lock()
		c.State = StateActive
		c.mu.Unlock()
		n.EnterChat(c.PeerID)
	} else {
		n.sendSessionMessage(c, MsgTypeDecline, "NO")
		n.closeStream(c)
		n.Log(LogLevelSuccess, "Отклонено")
	}
	n.listener.OnContactUpdate()
}

// Disconnect отменяет соединение или разрывает активный чат
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

	// Проверяем, есть ли что отменять
	if state == StateIdle && !isConnecting && !hasStream {
		n.Log(LogLevelWarning, "Нет активного соединения с %s", nick)
		return
	}

	// 1. Отменяем контекст подключения (для отмены DHT поиска)
	if cancelFunc != nil {
		cancelFunc()
	}

	// 2. Если мы в активном чате с этим контактом - выходим
	n.mu.Lock()
	wasActiveChat := n.activeChat == pid
	if wasActiveChat {
		n.activeChat = ""
	}
	n.mu.Unlock()

	if wasActiveChat {
		n.listener.OnChatChanged("", "")
	}

	// 3. Отправляем сообщение об отмене/завершении если есть сессия
	if hasStream && hasSession {
		switch state {
		case StatePendingOutgoing:
			// Отменяем исходящий запрос
			n.sendSessionMessage(c, MsgTypeCancel, "")
		case StatePendingIncoming:
			// Отклоняем входящий запрос
			n.sendSessionMessage(c, MsgTypeDecline, "")
		case StateActive:
			// Завершаем активный чат
			n.sendSessionMessage(c, MsgTypeBye, "")
		}
	}

	// 4. Закрываем соединение
	n.closeStream(c)

	// 5. Логируем результат
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

	n.listener.OnContactUpdate()
}

// DisconnectByPeerID - версия для GUI (по PeerID)
func (n *Node) DisconnectByPeerID(pid peer.ID) {
	c := n.getContactByID(pid)
	if c == nil {
		return
	}
	n.Disconnect(c.Nickname)
}

func (n *Node) EnterChat(id peer.ID) {
	n.mu.Lock()
	c := n.contacts[id]
	if c == nil {
		n.mu.Unlock()
		return
	}
	n.activeChat = id
	nick := c.Nickname
	n.mu.Unlock()

	n.listener.OnChatChanged(id.String(), nick)
	n.Log(LogLevelInfo, "ЧАТ: %s (Forward Secrecy: ON)", nick)
}

func (n *Node) LeaveChat() {
	n.mu.Lock()
	id := n.activeChat
	n.activeChat = ""
	n.mu.Unlock()

	n.listener.OnChatChanged("", "")

	if id == "" {
		return
	}

	c := n.getContactByID(id)
	if c != nil {
		n.sendSessionMessage(c, MsgTypeBye, "")
		n.closeStream(c)
		n.Log(LogLevelSuccess, "Чат завершён")
		n.listener.OnContactUpdate()
	}
}
func (n *Node) Logout() {
	// Отключаемся от всех контактов
	n.mu.Lock()
	contacts := make([]*Contact, 0, len(n.contacts))
	for _, c := range n.contacts {
		contacts = append(contacts, c)
	}
	n.activeChat = ""
	oldNick := n.nickname
	n.nickname = ""
	n.mu.Unlock()

	if oldNick == "" {
		n.Log(LogLevelWarning, "Вы не залогинены")
		return
	}

	// Закрываем все соединения
	for _, c := range contacts {
		c.mu.Lock()
		hasStream := c.Stream != nil
		hasSession := c.sessionEstab
		c.mu.Unlock()

		if hasStream && hasSession {
			n.sendSessionMessage(c, MsgTypeBye, "")
		}
		n.closeStream(c)
	}

	// Сохраняем identity без ника
	n.saveIdentity()

	n.listener.OnChatChanged("", "")
	n.listener.OnContactUpdate()
	n.Log(LogLevelSuccess, "Вы вышли из аккаунта")
}

// RemoveFriend удаляет контакт из списка
func (n *Node) RemoveFriend(nick string) {
	c := n.getContactByNick(nick)
	if c == nil {
		n.Log(LogLevelError, "Контакт '%s' не найден", nick)
		return
	}

	c.mu.Lock()
	pid := c.PeerID
	hasStream := c.Stream != nil
	hasSession := c.sessionEstab
	c.mu.Unlock()

	// Отключаемся если подключены
	if hasStream {
		if hasSession {
			n.sendSessionMessage(c, MsgTypeBye, "")
		}
		n.closeStream(c)
	}

	// Проверяем активный чат
	n.mu.Lock()
	wasActiveChat := n.activeChat == pid
	if wasActiveChat {
		n.activeChat = ""
	}

	// Удаляем из мапов
	delete(n.contacts, pid)
	delete(n.nickMap, nick)
	n.mu.Unlock()

	if wasActiveChat {
		n.listener.OnChatChanged("", "")
	}

	n.SaveContacts()
	n.listener.OnContactUpdate()
	n.Log(LogLevelSuccess, "Контакт '%s' удалён", nick)
}

// IsLoggedIn проверяет залогинен ли пользователь
func (n *Node) IsLoggedIn() bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.nickname != ""
}
