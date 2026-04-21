package f2f

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// --- Forward Secrecy Key Generation ---

func generateEphemeralKeys() (*[32]byte, *[32]byte, error) {
	var priv, pub [32]byte
	if _, err := io.ReadFull(rand.Reader, priv[:]); err != nil {
		return nil, nil, err
	}
	// Clamp private key for X25519
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	curve25519.ScalarBaseMult(&pub, &priv)
	return &priv, &pub, nil
}

// --- Double Ratchet Implementation ---

// InitializeRatchet создает начальное состояние Ratchet из общего секрета Handshake.
// isAlice = true для инициатора (Alice), false для ответчика (Bob).
func InitializeRatchet(sharedSecret, remotePub, localPriv, localPub *[32]byte, isInitiator bool) (*RatchetState, error) {
	rs := &RatchetState{
		SkippedMsgKeys: make(map[[36]byte]SkippedKey),
	}

	rs.RootKey = *sharedSecret

	if isInitiator {
		// ALICE (Initiator)
		// Генерируем новую пару ключей для Ratchet
		priv, pub, err := generateEphemeralKeys()
		if err != nil {
			return nil, err
		}
		rs.DHLocalPriv = priv
		rs.DHLocalPub = pub
		rs.DHRemotePub = remotePub // Bob's handshake public key

		// Alice делает первый DH step сразу
		shared, err := computeDH(rs.DHLocalPriv, rs.DHRemotePub)
		if err != nil {
			return nil, err
		}
		newRK, newCKs := kdfRK(&rs.RootKey, &shared)
		rs.RootKey = newRK
		rs.ChainKeyS = newCKs
		// ChainKeyR будет установлен когда Bob ответит
	} else {
		// BOB (Responder)
		// ВАЖНО: Используем handshake ключи как начальные DH ключи!
		// Это позволит Alice правильно установить shared secret
		rs.DHLocalPriv = localPriv
		rs.DHLocalPub = localPub
		// DHRemotePub пока nil - будет установлен при получении первого сообщения
	}

	return rs, nil
}

// RatchetEncrypt шифрует сообщение, продвигая Symmetric Chain.
// Возвращает: Header (plaintext), Ciphertext, Error
func (n *Node) RatchetEncrypt(rs *RatchetState, plaintext []byte) ([]byte, []byte, error) {
	// 1. Продвигаем Sending Chain
	newCKs, msgKey := kdfCK(&rs.ChainKeyS)
	rs.ChainKeyS = newCKs

	// 2. Формируем заголовок
	header := RatchetHeader{
		PublicKey: *rs.DHLocalPub,
		PN:        rs.PN,
		N:         rs.Ns,
	}
	headerBytes := header.Marshal()

	// 3. Шифруем (AEAD с header как associated data)
	// XChaCha20-Poly1305 требует nonce 24 байта.
	// В Signal nonce выводится из KDF, но XChaCha random nonce безопаснее.
	ciphertext, err := n.encryptXChaChaAD(plaintext, &msgKey, headerBytes)
	if err != nil {
		return nil, nil, err
	}

	rs.Ns++
	return headerBytes, ciphertext, nil
}

// RatchetDecrypt дешифрует сообщение, обрабатывая пропуски и DH steps.
func (n *Node) RatchetDecrypt(rs *RatchetState, headerBytes, ciphertext []byte) ([]byte, error) {
	var header RatchetHeader
	if err := header.Unmarshal(headerBytes); err != nil {
		return nil, fmt.Errorf("bad header: %v", err)
	}

	// 1. Попытка дешифровать сохраненными (пропущенными) ключами
	if plaintext, ok := n.trySkippedKeys(rs, &header, ciphertext, headerBytes); ok {
		return plaintext, nil
	}

	// 2. Проверяем нужен ли DH Ratchet step
	// ВАЖНО: rs.DHRemotePub может быть nil для Bob при первом сообщении
	needRatchet := rs.DHRemotePub == nil || header.PublicKey != *rs.DHRemotePub

	if needRatchet {
		// Сохраняем пропущенные ключи из *текущей* приемной цепочки
		if err := n.skipMessageKeys(rs, header.PN); err != nil {
			return nil, fmt.Errorf("skip keys error: %v", err)
		}

		// Выполняем DH Ratchet Step
		if err := n.dhRatchetStep(rs, &header.PublicKey); err != nil {
			return nil, fmt.Errorf("dh ratchet error: %v", err)
		}
	}

	// 3. Сохраняем пропущенные ключи в *новой* цепочке (если N перескочил)
	if err := n.skipMessageKeys(rs, header.N); err != nil {
		return nil, fmt.Errorf("skip keys current chain error: %v", err)
	}

	// 4. Продвигаем Receiving Chain и получаем Message Key
	newCKr, msgKey := kdfCK(&rs.ChainKeyR)
	rs.ChainKeyR = newCKr
	rs.Nr++

	// 5. Дешифруем
	plaintext, err := n.decryptXChaChaAD(ciphertext, &msgKey, headerBytes)
	if err != nil {
		return nil, fmt.Errorf("decrypt failed: %v", err)
	}

	return plaintext, nil
}

func (n *Node) trySkippedKeys(rs *RatchetState, h *RatchetHeader, ciphertext, ad []byte) ([]byte, bool) {
	// Ключ карты: PubKey + N
	var mapKey [36]byte
	copy(mapKey[0:32], h.PublicKey[:])
	binary.BigEndian.PutUint32(mapKey[32:36], h.N)

	if val, exists := rs.SkippedMsgKeys[mapKey]; exists {
		plaintext, err := n.decryptXChaChaAD(ciphertext, &val.Key, ad)
		if err == nil {
			delete(rs.SkippedMsgKeys, mapKey)
			return plaintext, true
		}
	}
	return nil, false
}

func (n *Node) skipMessageKeys(rs *RatchetState, until uint32) error {
	if rs.Nr+uint32(MaxSkipKeys) < until {
		return errors.New("too many skipped messages")
	}

	// Purge expired skipped keys before storing new ones.
	if cutoff := time.Now().Add(-MaxSkipKeyAge); len(rs.SkippedMsgKeys) > 0 {
		for k, v := range rs.SkippedMsgKeys {
			if v.Timestamp.Before(cutoff) {
				delete(rs.SkippedMsgKeys, k)
			}
		}
	}

	// Если ChainKeyR не инициализирован (первый шаг), пропускать нечего
	var empty [32]byte
	if rs.ChainKeyR == empty {
		return nil
	}

	// Если DHRemotePub nil (Bob до первого сообщения), пропускать нечего
	if rs.DHRemotePub == nil {
		return nil
	}

	for rs.Nr < until {
		newCKr, msgKey := kdfCK(&rs.ChainKeyR)
		rs.ChainKeyR = newCKr

		var mapKey [36]byte
		copy(mapKey[0:32], rs.DHRemotePub[:])
		binary.BigEndian.PutUint32(mapKey[32:36], rs.Nr)

		rs.SkippedMsgKeys[mapKey] = SkippedKey{
			Key:       msgKey,
			Timestamp: time.Now(),
		}
		rs.Nr++
	}
	return nil
}

func (n *Node) dhRatchetStep(rs *RatchetState, remotePub *[32]byte) error {
	rs.PN = rs.Ns
	rs.Ns = 0
	rs.Nr = 0
	rs.DHRemotePub = remotePub

	// Root KDF 1: R_k + DH(Local, Remote) -> New R_k, ChainKeyR
	sharedReceive, err := computeDH(rs.DHLocalPriv, remotePub)
	if err != nil {
		return err
	}
	rs.RootKey, rs.ChainKeyR = kdfRK(&rs.RootKey, &sharedReceive)

	// Генерируем новый ключ для отправки
	priv, pub, err := generateEphemeralKeys()
	if err != nil {
		return err
	}
	rs.DHLocalPriv = priv
	rs.DHLocalPub = pub

	// Root KDF 2: R_k + DH(NewLocal, Remote) -> New R_k, ChainKeyS
	sharedSend, err := computeDH(rs.DHLocalPriv, remotePub)
	if err != nil {
		return err
	}
	rs.RootKey, rs.ChainKeyS = kdfRK(&rs.RootKey, &sharedSend)

	return nil
}

// --- KDF Helpers ---

// computeDH: X25519(priv, pub). Rejects low-order points (returns error
// on all-zero output).
func computeDH(priv, pub *[32]byte) ([32]byte, error) {
	var out [32]byte
	shared, err := curve25519.X25519(priv[:], pub[:])
	if err != nil {
		return out, fmt.Errorf("x25519: %w", err)
	}
	copy(out[:], shared)
	return out, nil
}

// kdfRK: HKDF(root_key, dh_out) -> (root_key, chain_key)
func kdfRK(rootKey, dhOut *[32]byte) ([32]byte, [32]byte) {
	// Salt = RootKey, IKM = DH Output
	hkdfReader := hkdf.New(sha256.New, dhOut[:], rootKey[:], InfoRootKey)

	var out [64]byte
	io.ReadFull(hkdfReader, out[:])

	var newRoot [32]byte
	var newChain [32]byte
	copy(newRoot[:], out[0:32])
	copy(newChain[:], out[32:64])

	return newRoot, newChain
}

// kdfCK: HMAC(chain_key) -> (next_chain_key, msg_key).
// Canonical Signal spec: MsgKey = HMAC(CK, 0x01), NextCK = HMAC(CK, 0x02).
func kdfCK(chainKey *[32]byte) ([32]byte, [32]byte) {
	var nextChain, msgKey [32]byte

	h := hmac.New(sha256.New, chainKey[:])
	h.Write([]byte{0x01})
	copy(msgKey[:], h.Sum(nil))

	h.Reset()
	h.Write([]byte{0x02})
	copy(nextChain[:], h.Sum(nil))

	return nextChain, msgKey
}

// --- XChaCha20-Poly1305 with AD ---

func (n *Node) encryptXChaChaAD(plaintext []byte, key *[32]byte, ad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plaintext)+aead.Overhead())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return aead.Seal(nonce, nonce, plaintext, ad), nil
}

func (n *Node) decryptXChaChaAD(ciphertext []byte, key *[32]byte, ad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aead.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	nonce, encrypted := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]
	return aead.Open(nil, nonce, encrypted, ad)
}

// --- Legacy & Helpers ---

// handshakeSigContext is prepended to the signed payload so that a signature
// produced under this libp2p identity key for some other protocol cannot be
// replayed here (cross-protocol replay protection via domain separation).
const handshakeSigContext = "F2F-Handshake-v1:"

// handshakeSigBytes builds the byte-string that gets signed/verified.
func handshakeSigBytes(version string, ts, nonce int64, naclPub, ephPub []byte) []byte {
	buf := new(bytes.Buffer)
	buf.WriteString(handshakeSigContext)
	buf.WriteString(version)
	binary.Write(buf, binary.BigEndian, ts)
	binary.Write(buf, binary.BigEndian, nonce)
	buf.Write(naclPub)
	buf.Write(ephPub)
	return buf.Bytes()
}

// createHandshakeBytes creates signed handshake payload
func (n *Node) createHandshakeBytes(ephPub *[32]byte) ([]byte, error) {
	privKey := n.host.Peerstore().PrivKey(n.host.ID())
	var nonce int64

	if err := binary.Read(rand.Reader, binary.LittleEndian, &nonce); err != nil {
		return nil, err
	}

	payload := HandshakePayload{
		Version:      ProtocolVersion,
		Timestamp:    time.Now().UnixNano(),
		Nonce:        nonce,
		NaClPubKey:   n.naclPublic[:],
		EphemeralPub: ephPub[:],
	}

	sig, err := privKey.Sign(handshakeSigBytes(payload.Version, payload.Timestamp, payload.Nonce, payload.NaClPubKey, payload.EphemeralPub))
	if err != nil {
		return nil, err
	}
	payload.Signature = sig

	return payload.Marshal(), nil
}

func (n *Node) verifyHandshake(c *Contact, data []byte) (*[32]byte, error) {
	if len(data) > HandshakeLimit {
		return nil, errors.New("too large")
	}

	var payload HandshakePayload
	if err := payload.Unmarshal(data); err != nil {
		return nil, fmt.Errorf("decode handshake: %w", err)
	}

	if payload.Version != ProtocolVersion {
		return nil, fmt.Errorf("protocol version mismatch: got %q, want %q", payload.Version, ProtocolVersion)
	}

	if len(payload.EphemeralPub) != 32 {
		return nil, errors.New("bad eph key")
	}

	// Check timestamp first (cheap)
	now := time.Now()
	ts := time.Unix(0, payload.Timestamp)
	if now.Sub(ts) > MaxTimeSkew || ts.Sub(now) > MaxTimeSkew {
		return nil, errors.New("time skew")
	}

	// Verify signature BEFORE touching replay cache, so a forged handshake
	// cannot pollute SeenNonces (even though the libp2p transport already
	// authenticates the peer, keep the ordering defensively correct).
	remotePub := n.host.Peerstore().PubKey(c.PeerID)
	if remotePub == nil {
		return nil, errors.New("no key")
	}

	sigBytes := handshakeSigBytes(payload.Version, payload.Timestamp, payload.Nonce, payload.NaClPubKey, payload.EphemeralPub)
	ok, _ := remotePub.Verify(sigBytes, payload.Signature)
	if !ok {
		return nil, errors.New("bad sig")
	}

	// Constant-time compare of the long-term identity pubkey.
	if len(payload.NaClPubKey) != 32 || subtle.ConstantTimeCompare(payload.NaClPubKey, c.PublicKey[:]) != 1 {
		return nil, errors.New("key mismatch")
	}

	// Replay protection — only after cryptographic auth passes.
	c.mu.Lock()
	if c.SeenNonces == nil {
		c.SeenNonces = make(map[int64]time.Time)
	}
	for k, t := range c.SeenNonces {
		if time.Since(t) > MaxTimeSkew {
			delete(c.SeenNonces, k)
		}
	}
	if len(c.SeenNonces) >= MaxNoncesPerContact {
		c.mu.Unlock()
		return nil, errors.New("flood")
	}
	if _, exists := c.SeenNonces[payload.Nonce]; exists {
		c.mu.Unlock()
		return nil, errors.New("replay")
	}
	c.SeenNonces[payload.Nonce] = time.Now()
	c.mu.Unlock()

	var ephPub [32]byte
	copy(ephPub[:], payload.EphemeralPub)
	return &ephPub, nil
}

// deriveSessionKey используется ТОЛЬКО для начального handshake, чтобы получить RootKey
func deriveSessionKey(localPriv, localPub, remotePub *[32]byte) (*[32]byte, error) {
	sharedSlice, err := curve25519.X25519(localPriv[:], remotePub[:])
	if err != nil {
		return nil, fmt.Errorf("x25519: %w", err)
	}
	var shared [32]byte
	copy(shared[:], sharedSlice)

	var saltBuf bytes.Buffer
	saltBuf.WriteString("f2f-init-v1:")
	if bytes.Compare(localPub[:], remotePub[:]) < 0 {
		saltBuf.Write(localPub[:])
		saltBuf.Write(remotePub[:])
	} else {
		saltBuf.Write(remotePub[:])
		saltBuf.Write(localPub[:])
	}

	hkdfReader := hkdf.New(sha256.New, shared[:], saltBuf.Bytes(), []byte("session-root-deriv"))
	var sessionKey [32]byte
	if _, err := io.ReadFull(hkdfReader, sessionKey[:]); err != nil {
		return nil, err
	}

	// Zero shared
	for i := range shared {
		shared[i] = 0
	}
	return &sessionKey, nil
}

// sasContext domain-separates SAS derivation so the code can't collide with
// any other hash produced in this protocol.
const sasContext = "F2F-SAS-v1:"

// ComputeSAS returns a short session authentication string derived from both
// parties' handshake ephemeral public keys. Both sides MUST produce identical
// output when given the same pair of keys. Verified out-of-band (voice/video)
// to rule out MITM: attacker would have to run two handshakes whose SAS collide,
// which for 64-bit SAS means ~2^32 parallel sessions (birthday bound).
//
// Format: 4 dash-separated groups of 4 hex chars → "AB12-CD34-EF56-7890".
func ComputeSAS(pub1, pub2 []byte) string {
	low, high := pub1, pub2
	if bytes.Compare(pub1, pub2) > 0 {
		low, high = pub2, pub1
	}
	h := sha256.New()
	h.Write([]byte(sasContext))
	h.Write(low)
	h.Write(high)
	sum := h.Sum(nil)
	hex := fmt.Sprintf("%X", sum[:8]) // 64 bits
	return fmt.Sprintf("%s-%s-%s-%s", hex[0:4], hex[4:8], hex[8:12], hex[12:16])
}

// ComputeFingerprint returns a 160-bit hex fingerprint of the given public key,
// formatted as 10 dash-separated groups of 4 hex characters.
// 160 bits gives ~2^80 preimage resistance — acceptable for manual OOB verification.
func ComputeFingerprint(pubKey []byte) string {
	hash := sha256.Sum256(pubKey)
	h := fmt.Sprintf("%X", hash[:20]) // 20 bytes = 160 bits = 40 hex chars
	groups := make([]string, 10)
	for i := 0; i < 10; i++ {
		groups[i] = h[i*4 : (i+1)*4]
	}
	return strings.Join(groups, "-")
}
