package f2f

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
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
func InitializeRatchet(sharedSecret *[32]byte, bobPub *[32]byte) (*RatchetState, error) {
	rs := &RatchetState{
		SkippedMsgKeys: make(map[[36]byte]SkippedKey),
	}

	// Инициализация Root Chain из shared secret
	// В Signal обычно делается сложнее (3-way handshake), но мы адаптируем существующий 2-way.
	// Используем sharedSecret как начальный RootKey.
	rs.RootKey = *sharedSecret

	if bobPub != nil {
		// ALICE (Initiator)
		// У нас уже есть ключ Bob'a (из Handshake), и у нас есть наш Initial Key.
		// Генерируем новый Ratchet Key pair сразу.
		priv, pub, err := generateEphemeralKeys()
		if err != nil {
			return nil, err
		}
		rs.DHLocalPriv = priv
		rs.DHLocalPub = pub
		rs.DHRemotePub = bobPub

		// Alice делает первый DH шаг сразу, так как она знает ключ Боба
		shared := computeDH(rs.DHLocalPriv, rs.DHRemotePub)
		newRK, newCKs := kdfRK(&rs.RootKey, &shared)
		rs.RootKey = newRK
		rs.ChainKeyS = newCKs
		// ChainKeyR останется пустым, пока Боб не ответит
	} else {
		// BOB (Responder)
		// У нас пока нет Ratchet ключа, мы просто знаем RootKey (SharedSecret).
		// Мы сохраним Handshake ключи как "Local", но для первого шага используем логику приема.
		// В текущей реализации (f2f handshake) Боб сгенерировал EphemeralPub в handshake.
		// Это и будет его "текущий" Ratchet Key.
		// Примечание: Это упрощение. В идеале нужен новый обмен.
		// Но мы просто инициализируем пару пустыми значениями и будем ждать первого заголовка от Алисы.

		// Боб сгенерирует ключи при первом Ratchet step
		priv, pub, err := generateEphemeralKeys()
		if err != nil {
			return nil, err
		}
		rs.DHLocalPriv = priv
		rs.DHLocalPub = pub
		// RemotePub пока неизвестен (в контексте Ratchet), он придет в заголовке
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

	// 2. Если пришел новый DH ключ (Ratchet Step)
	if header.PublicKey != *rs.DHRemotePub {
		// Проверяем, не слишком ли далеко ушел шаг (Anti-DoS)
		// Для упрощения пропускаем строгую проверку лимита шагов, но в продакшене нужна.

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

	// Если ChainKeyR не инициализирован (первый шаг), пропускать нечего
	var empty [32]byte
	if rs.ChainKeyR == empty {
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
	sharedReceive := computeDH(rs.DHLocalPriv, remotePub)
	rs.RootKey, rs.ChainKeyR = kdfRK(&rs.RootKey, &sharedReceive)

	// Генерируем новый ключ для отправки
	priv, pub, err := generateEphemeralKeys()
	if err != nil {
		return err
	}
	rs.DHLocalPriv = priv
	rs.DHLocalPub = pub

	// Root KDF 2: R_k + DH(NewLocal, Remote) -> New R_k, ChainKeyS
	sharedSend := computeDH(rs.DHLocalPriv, remotePub)
	rs.RootKey, rs.ChainKeyS = kdfRK(&rs.RootKey, &sharedSend)

	return nil
}

// --- KDF Helpers ---

// computeDH: X25519(priv, pub)
func computeDH(priv, pub *[32]byte) [32]byte {
	var shared [32]byte
	curve25519.ScalarMult(&shared, priv, pub)
	return shared
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

// kdfCK: HMAC(chain_key) -> (chain_key, msg_key)
func kdfCK(chainKey *[32]byte) ([32]byte, [32]byte) {
	// HMAC-SHA256
	// MsgKey = HMAC(ChainKey, "1")
	// NextChainKey = HMAC(ChainKey, "2")

	h := hmac.New(sha256.New, chainKey[:])
	h.Write([]byte{0x01})
	res1 := h.Sum(nil) // Используем часть как ключ

	h.Reset()
	h.Write([]byte{0x02})
	res2 := h.Sum(nil)

	// KDF обычно требует 32 байта для ключа
	// Используем HKDF expander или просто SHA256 output,
	// но HMAC-SHA256 уже дает 32 байта, что подходит.

	// Чтобы строго соответствовать Signal spec, там используются константы 0x01, 0x02
	// и HMAC как KDF.
	// Мы дополнительно прогоним через HKDF-Expand для чистоты изоляции (InfoMsgKey).

	// Message Key Derivation
	mkReader := hkdf.Expand(sha256.New, res1, InfoMsgKey)
	var msgKey [32]byte
	io.ReadFull(mkReader, msgKey[:])

	// Chain Key Derivation
	ckReader := hkdf.Expand(sha256.New, res2, InfoChainKey)
	var nextChain [32]byte
	io.ReadFull(ckReader, nextChain[:])

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

	buf := new(bytes.Buffer)
	buf.WriteString(payload.Version)
	binary.Write(buf, binary.BigEndian, payload.Timestamp)
	binary.Write(buf, binary.BigEndian, payload.Nonce)
	buf.Write(payload.NaClPubKey)
	buf.Write(payload.EphemeralPub)

	sig, err := privKey.Sign(buf.Bytes())
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

	// Разрешаем старые версии, если нужно, но лучше строгий чек
	if payload.Version != ProtocolVersion {
		// Log warning?
	}

	if len(payload.EphemeralPub) != 32 {
		return nil, errors.New("bad eph key")
	}

	// Check timestamp
	now := time.Now()
	ts := time.Unix(0, payload.Timestamp)
	if now.Sub(ts) > MaxTimeSkew || ts.Sub(now) > MaxTimeSkew {
		return nil, errors.New("time skew")
	}

	// Replay protection
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

	// Verify signature
	remotePub := n.host.Peerstore().PubKey(c.PeerID)
	if remotePub == nil {
		return nil, errors.New("no key")
	}

	buf := new(bytes.Buffer)
	buf.WriteString(payload.Version)
	binary.Write(buf, binary.BigEndian, payload.Timestamp)
	binary.Write(buf, binary.BigEndian, payload.Nonce)
	buf.Write(payload.NaClPubKey)
	buf.Write(payload.EphemeralPub)

	ok, _ := remotePub.Verify(buf.Bytes(), payload.Signature)
	if !ok {
		return nil, errors.New("bad sig")
	}

	var recKey [32]byte
	copy(recKey[:], payload.NaClPubKey)
	if recKey != c.PublicKey {
		return nil, errors.New("key mismatch")
	}

	var ephPub [32]byte
	copy(ephPub[:], payload.EphemeralPub)
	return &ephPub, nil
}

// deriveSessionKey используется ТОЛЬКО для начального handshake, чтобы получить RootKey
func deriveSessionKey(localPriv, localPub, remotePub *[32]byte) (*[32]byte, error) {
	var shared [32]byte
	curve25519.ScalarMult(&shared, localPriv, remotePub)

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

func ComputeFingerprint(pubKey []byte) string {
	hash := sha256.Sum256(pubKey)
	hex := fmt.Sprintf("%X", hash[:8])
	return fmt.Sprintf("%s-%s-%s-%s", hex[0:4], hex[4:8], hex[8:12], hex[12:16])
}
