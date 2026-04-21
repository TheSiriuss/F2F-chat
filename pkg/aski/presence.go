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

	// Prefer live signals over DHT: an open chat stream or an active
	// libp2p connection means we're IN CONTACT with this peer right now.
	// Only fall back to DHT when neither holds.
	c.mu.Lock()
	hasStream := c.Stream != nil
	c.mu.Unlock()

	if conn := n.host.Network().Connectedness(pid); hasStream || conn == network.Connected || conn == network.Limited {
		addrs := n.host.Peerstore().Addrs(pid)
		c.mu.Lock()
		c.Presence = PresenceOnline
		c.LastSeen = time.Now()
		c.AddressCount = len(addrs)
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
	// Treat "FindPeer returned a record with zero addresses" the same as a
	// DHT error — we can't actually reach the peer, so calling them
	// "online" is a lie that causes .connect to fail immediately after.
	if err != nil || len(info.Addrs) == 0 {
		c.Presence = PresenceOffline
		c.AddressCount = 0
		c.FailCount++
		// Cap shift amount to avoid int overflow on long-running offline peers.
		shift := c.FailCount
		if shift > 8 {
			shift = 8
		}
		backoff := time.Duration(30*(1<<shift)) * time.Second
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
		n.host.Peerstore().AddAddrs(pid, info.Addrs, peerstore.TempAddrTTL)
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
	hasStream := c.Stream != nil
	c.mu.Unlock()

	// Short-circuit: if we ALREADY have a live libp2p connection to the
	// peer (or an open chat stream), we're definitively in contact with
	// them — going to DHT is wasted work and, worse, returns a stale
	// "offline" verdict when the DHT record is out-of-date. The live
	// connection is the source of truth.
	if conn := n.host.Network().Connectedness(pid); hasStream || conn == network.Connected || conn == network.Limited {
		addrs := n.host.Peerstore().Addrs(pid)
		c.mu.Lock()
		c.Presence = PresenceOnline
		c.LastSeen = time.Now()
		c.AddressCount = len(addrs)
		c.FailCount = 0
		c.LastChecked = time.Now()
		c.mu.Unlock()
		n.Log(LogLevelSuccess, "%s — уже в сети (живое соединение, %d адресов в peerstore)",
			nick, len(addrs))
		n.listener.OnContactUpdate()
		return
	}

	n.Log(LogLevelInfo, "Поиск %s в DHT...", nick)

	ctx, cancel := context.WithTimeout(n.ctx, PresenceTimeout)
	defer cancel()

	start := time.Now()
	info, err := n.dht.FindPeer(ctx, pid)
	elapsed := time.Since(start)

	c.mu.Lock()
	c.LastChecked = time.Now()
	switch {
	case err != nil:
		c.Presence = PresenceOffline
		c.AddressCount = 0
		c.mu.Unlock()
		n.Log(LogLevelError, "%s не найден (%.1fs): %v", nick, elapsed.Seconds(), err)
	case len(info.Addrs) == 0:
		c.Presence = PresenceOffline
		c.AddressCount = 0
		c.mu.Unlock()
		n.Log(LogLevelWarning, "%s — peerID в DHT есть, но адресов 0 (запись устарела / контакт не в сети)", nick)
	default:
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
