package f2f

import (
	"context"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
)

func (n *Node) presenceLoop() {
	defer n.wg.Done()
	select {
	case <-time.After(10 * time.Second):
	case <-n.ctx.Done():
		return
	}
	n.QueuePresenceChecks()
	ticker := time.NewTicker(PresenceInterval)
	defer ticker.Stop()
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
			n.QueuePresenceChecks()
		}
	}
}

func (n *Node) presenceWorkerPool() {
	defer n.wg.Done()
	for {
		select {
		case <-n.ctx.Done():
			return
		case pid, ok := <-n.presenceChan:
			if !ok {
				return
			}
			n.checkSinglePresence(pid)
		}
	}
}

func (n *Node) ForceCheckAll() {
	n.mu.RLock()
	contacts := make([]*Contact, 0, len(n.contacts))
	for _, c := range n.contacts {
		contacts = append(contacts, c)
	}
	n.mu.RUnlock()

	for _, c := range contacts {
		c.mu.Lock()
		c.NextCheckTime = time.Now()
		c.FailCount = 0
		c.Presence = PresenceChecking
		pid := c.PeerID
		c.mu.Unlock()

		select {
		case n.presenceChan <- pid:
		default:
		}
	}

	n.listener.OnContactUpdate()
}

func (n *Node) QueuePresenceChecks() {
	n.mu.RLock()
	contacts := make([]*Contact, 0, len(n.contacts))
	for _, c := range n.contacts {
		contacts = append(contacts, c)
	}
	n.mu.RUnlock()

	needUpdate := false
	for _, c := range contacts {
		c.mu.Lock()
		if c.Stream != nil {
			c.Presence = PresenceOnline
			c.LastSeen = time.Now()
			c.FailCount = 0
			c.mu.Unlock()
			continue
		}
		if time.Now().Before(c.NextCheckTime) {
			c.mu.Unlock()
			continue
		}
		c.Presence = PresenceChecking
		pid := c.PeerID
		needUpdate = true
		c.mu.Unlock()

		select {
		case n.presenceChan <- pid:
		default:
		}
	}

	if needUpdate {
		n.listener.OnContactUpdate()
	}
}

func (n *Node) checkSinglePresence(pid peer.ID) {
	c := n.getContactByID(pid)
	if c == nil {
		return
	}

	if n.host.Network().Connectedness(pid) == network.Connected {
		c.mu.Lock()
		c.Presence = PresenceOnline
		c.LastSeen = time.Now()
		c.FailCount = 0
		c.NextCheckTime = time.Now().Add(PresenceInterval)
		c.mu.Unlock()
		n.listener.OnContactUpdate()
		return
	}

	ctx, cancel := context.WithTimeout(n.ctx, PresenceTimeout)
	defer cancel()
	info, err := n.dht.FindPeer(ctx, pid)

	c.mu.Lock()
	c.LastChecked = time.Now()
	if err != nil {
		c.Presence = PresenceOffline
		c.FailCount++
		backoff := time.Duration(30*(1<<c.FailCount)) * time.Second
		if backoff > MaxPresenceBackoff {
			backoff = MaxPresenceBackoff
		}
		c.NextCheckTime = time.Now().Add(backoff)
	} else {
		c.Presence = PresenceOnline
		c.LastSeen = time.Now()
		c.AddressCount = len(info.Addrs)
		c.FailCount = 0
		c.NextCheckTime = time.Now().Add(PresenceInterval)
		if len(info.Addrs) > 0 {
			n.host.Peerstore().AddAddrs(pid, info.Addrs, peerstore.TempAddrTTL)
		}
	}
	c.mu.Unlock()

	n.listener.OnContactUpdate()
}

func (n *Node) FindContact(nick string) {
	c := n.getContactByNick(nick)
	if c == nil {
		n.Log(LogLevelError, "Контакт '%s' не найден", nick)
		return
	}

	c.mu.Lock()
	pid := c.PeerID
	c.mu.Unlock()

	n.Log(LogLevelInfo, "Поиск %s в DHT...", nick)

	ctx, cancel := context.WithTimeout(n.ctx, PresenceTimeout)
	defer cancel()

	start := time.Now()
	info, err := n.dht.FindPeer(ctx, pid)
	elapsed := time.Since(start)

	c.mu.Lock()
	c.LastChecked = time.Now()
	if err != nil {
		c.Presence = PresenceOffline
		c.mu.Unlock()
		n.Log(LogLevelError, "%s не найден (%.1fs)", nick, elapsed.Seconds())
	} else {
		c.Presence = PresenceOnline
		c.LastSeen = time.Now()
		c.AddressCount = len(info.Addrs)
		c.FailCount = 0
		c.mu.Unlock()
		n.host.Peerstore().AddAddrs(pid, info.Addrs, peerstore.PermanentAddrTTL)
		n.Log(LogLevelSuccess, "%s найден! (%d адресов, %.1fs)", nick, len(info.Addrs), elapsed.Seconds())
	}

	n.listener.OnContactUpdate()
}
