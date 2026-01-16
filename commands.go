package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"time"

	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

// Login sets the user's nickname
func (n *Node) Login(nickname string) {
	n.mu.Lock()
	n.nickname = nickname
	n.mu.Unlock()
	n.saveIdentity()
	n.SafePrintf("%s Вы: %s\n", Style.OK, nickname)
	go func() {
		time.Sleep(100 * time.Millisecond)
		n.ShowInfo()
	}()
}

// ShowInfo displays user information
func (n *Node) ShowInfo() {
	if n.nickname == "" {
		n.SafePrintf("%s Сначала: .login <ник>\n", Style.Warning)
		return
	}

	hasRelay := false
	for _, addr := range n.host.Addrs() {
		if strings.Contains(addr.String(), "p2p-circuit") {
			hasRelay = true
			break
		}
	}
	connectedPeers := len(n.host.Network().Peers())

	var statusLine string
	if hasRelay {
		statusLine = Style.Global + " GLOBAL (relay)"
	} else if connectedPeers > 0 {
		statusLine = Style.Searching + " ONLINE"
	} else {
		statusLine = Style.Offline + " OFFLINE"
	}

	pubKeyB64 := base64.StdEncoding.EncodeToString(n.naclPublic[:])
	addCmd := fmt.Sprintf(".addfriend %s %s %s", n.nickname, n.host.ID().String(), pubKeyB64)
	fp := computeFingerprint(n.naclPublic[:])

	n.drawBox("ВАШИ ДАННЫЕ", []string{
		fmt.Sprintf("Ник:         %s", n.nickname),
		fmt.Sprintf("Статус:      %s", statusLine),
		fmt.Sprintf("Пиров:       %d", connectedPeers),
		fmt.Sprintf("Fingerprint: %s", fp),
		"",
		"PeerID:",
		n.host.ID().String(),
		"",
		"Для друга:",
		addCmd,
	})
}

// ShowFingerprint shows key fingerprint
func (n *Node) ShowFingerprint(nick string) {
	if nick == "" {
		fp := computeFingerprint(n.naclPublic[:])
		n.drawBox("ВАШ FINGERPRINT", []string{
			"Сравните по телефону/лично:",
			"",
			fp,
		})
		return
	}

	c := n.getContactByNick(nick)
	if c == nil {
		n.SafePrintf("%s Контакт '%s' не найден\n", Style.Fail, nick)
		return
	}

	fp := computeFingerprint(c.PublicKey[:])
	n.drawBox(fmt.Sprintf("FINGERPRINT: %s", nick), []string{
		"Должно совпасть с .fingerprint у друга:",
		"",
		fp,
	})
}

// ConnectToBootstrap connects to DHT bootstrap nodes
func (n *Node) ConnectToBootstrap() {
	n.SafePrintf("%s Подключение к DHT...\n", Style.Info)
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
		n.SafePrintf("%s Подключено к %d узлам\n", Style.OK, connected)
		go func() {
			time.Sleep(3 * time.Second)
			n.ForceCheckAll()
		}()
	} else {
		n.SafePrintf("%s Не удалось подключиться\n", Style.Fail)
	}
}

// AddFriend adds a new contact
func (n *Node) AddFriend(nickname, peerIDStr, pubKeyB64 string) {
	if nickname == "" {
		n.SafePrintf("%s Пустой ник\n", Style.Fail)
		return
	}
	peerID, err := peer.Decode(peerIDStr)
	if err != nil {
		n.SafePrintf("%s Ошибка PeerID\n", Style.Fail)
		return
	}
	if peerID == n.host.ID() {
		n.SafePrintf("%s Нельзя добавить себя\n", Style.Fail)
		return
	}

	pubBytes, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil || len(pubBytes) != 32 {
		n.SafePrintf("%s Ошибка ключа\n", Style.Fail)
		return
	}
	var pubKey [32]byte
	copy(pubKey[:], pubBytes)

	n.mu.Lock()
	if _, exists := n.nickMap[nickname]; exists {
		n.mu.Unlock()
		n.SafePrintf("%s Ник '%s' занят\n", Style.Fail, nickname)
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

	fp := computeFingerprint(pubKey[:])
	n.SafePrintf("%s Добавлен: %s (FP: %s)\n", Style.OK, nickname, fp)

	go n.SaveContacts()
	go func() {
		time.Sleep(1 * time.Second)
		n.FindContact(nickname)
	}()
}

// HandleDecision handles accept/decline of chat request
func (n *Node) HandleDecision(nick string, accept bool) {
	c := n.getContactByNick(nick)
	if c == nil {
		n.SafePrintf("%s Контакт '%s' не найден\n", Style.Fail, nick)
		return
	}
	c.mu.Lock()
	isPending := c.State == StatePending
	hasSession := c.sessionEstab
	c.mu.Unlock()

	if !isPending || !hasSession {
		n.SafePrintf("%s Нет запроса от %s\n", Style.Warning, nick)
		return
	}

	if accept {
		if err := n.sendSessionMessage(c, MsgTypeAccept, "OK"); err != nil {
			n.SafePrintf("%s Ошибка: %v\n", Style.Fail, err)
			return
		}
		c.mu.Lock()
		c.State = StateActive
		c.mu.Unlock()
		n.enterChat(c.PeerID)
	} else {
		n.sendSessionMessage(c, MsgTypeDecline, "NO")
		n.closeStream(c)
		n.SafePrintf("%s Отклонено\n", Style.OK)
	}
}

// enterChat enters active chat with contact
func (n *Node) enterChat(id peer.ID) {
	n.mu.Lock()
	c := n.contacts[id]
	if c == nil {
		n.mu.Unlock()
		return
	}
	n.activeChat = id
	nick := c.Nickname
	n.mu.Unlock()

	n.updatePrompt()
	n.drawBox(fmt.Sprintf("ЧАТ: %s", nick), []string{
		"Forward Secrecy: ON",
		".leave - выход",
	})
}

// LeaveChat leaves current chat
func (n *Node) LeaveChat() {
	n.mu.Lock()
	id := n.activeChat
	n.activeChat = ""
	n.mu.Unlock()

	n.updatePrompt()

	if id == "" {
		n.SafePrintf("%s Вы не в чате\n", Style.Warning)
		return
	}

	c := n.getContactByID(id)
	if c != nil {
		n.sendSessionMessage(c, MsgTypeBye, "")
		n.closeStream(c)
		n.SafePrintf("%s Чат завершён\n", Style.OK)
	}
}

// ListContacts displays all contacts with status
func (n *Node) ListContacts() {
	n.mu.RLock()
	contacts := make([]*Contact, 0, len(n.contacts))
	for _, c := range n.contacts {
		contacts = append(contacts, c)
	}
	n.mu.RUnlock()

	var lines []string
	if len(contacts) == 0 {
		lines = append(lines, "(пусто)")
	}

	for _, c := range contacts {
		c.mu.Lock()
		state := c.State
		nick := c.Nickname
		hasStream := c.Stream != nil
		hasSession := c.sessionEstab
		presence := c.Presence
		lastSeen := c.LastSeen
		addrCount := c.AddressCount
		failCount := c.FailCount
		c.mu.Unlock()

		var icon, statusText string

		if hasStream && state == StateActive && hasSession {
			icon = Style.InChat
			statusText = "В ЧАТЕ"
		} else if hasStream && hasSession {
			icon = Style.Connected
			statusText = "CONNECTED"
		} else if state == StatePending {
			icon = Style.Pending
			statusText = "PENDING"
		} else {
			switch presence {
			case PresenceOnline:
				icon = Style.Online
				ago := time.Since(lastSeen).Round(time.Second)
				if addrCount > 0 {
					statusText = fmt.Sprintf("ONLINE (%d, %v)", addrCount, ago)
				} else {
					statusText = fmt.Sprintf("ONLINE (%v)", ago)
				}
			case PresenceOffline:
				icon = Style.Offline
				statusText = fmt.Sprintf("OFFLINE (%d)", failCount)
			case PresenceChecking:
				icon = Style.Searching
				statusText = "..."
			default:
				icon = Style.Unknown
				statusText = "?"
			}
		}

		lines = append(lines, fmt.Sprintf("%s %-12s %s", icon, nick, statusText))
	}

	n.drawBox("КОНТАКТЫ", lines)
}
