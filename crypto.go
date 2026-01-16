package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/nacl/secretbox"
)

// --- Forward Secrecy Key Generation ---

// generateEphemeralKeys creates a new X25519 key pair
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

// deriveSessionKey derives a session key from ephemeral keys using HKDF
func deriveSessionKey(localPriv, localPub, remotePub *[32]byte) (*[32]byte, error) {
	var shared [32]byte
	curve25519.ScalarMult(&shared, localPriv, remotePub)

	// Create deterministic salt from both public keys
	var saltBuf bytes.Buffer
	saltBuf.WriteString("f2f-session-v1:")
	if bytes.Compare(localPub[:], remotePub[:]) < 0 {
		saltBuf.Write(localPub[:])
		saltBuf.Write(remotePub[:])
	} else {
		saltBuf.Write(remotePub[:])
		saltBuf.Write(localPub[:])
	}

	hkdfReader := hkdf.New(sha256.New, shared[:], saltBuf.Bytes(), []byte("session-key"))
	var sessionKey [32]byte
	if _, err := io.ReadFull(hkdfReader, sessionKey[:]); err != nil {
		return nil, err
	}

	// Zero shared secret
	for i := range shared {
		shared[i] = 0
	}

	return &sessionKey, nil
}

// --- Session Encryption ---

// encryptSession encrypts a message with the session key
func (n *Node) encryptSession(msg *InnerMessage, sessionKey *[32]byte) ([]byte, error) {
	plaintext, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}

	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}

	encrypted := secretbox.Seal(nonce[:], plaintext, &nonce, sessionKey)
	return encrypted, nil
}

// decryptSession decrypts a message with the session key
func (n *Node) decryptSession(ciphertext []byte, sessionKey *[32]byte) (*InnerMessage, error) {
	if len(ciphertext) < 24+secretbox.Overhead {
		return nil, errors.New("ciphertext too short")
	}

	var nonce [24]byte
	copy(nonce[:], ciphertext[:24])

	plaintext, ok := secretbox.Open(nil, ciphertext[24:], &nonce, sessionKey)
	if !ok {
		return nil, errors.New("decryption failed")
	}

	var msg InnerMessage
	if err := json.Unmarshal(plaintext, &msg); err != nil {
		return nil, err
	}

	return &msg, nil
}

// --- Handshake ---

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
	binary.Write(buf, binary.LittleEndian, payload.Timestamp)
	binary.Write(buf, binary.LittleEndian, payload.Nonce)
	buf.Write(payload.NaClPubKey)
	buf.Write(payload.EphemeralPub)

	sig, err := privKey.Sign(buf.Bytes())
	if err != nil {
		return nil, err
	}
	payload.Signature = sig

	return json.Marshal(payload)
}

// verifyHandshake verifies incoming handshake and returns remote ephemeral key
func (n *Node) verifyHandshake(c *Contact, data []byte) (*[32]byte, error) {
	if len(data) > HandshakeLimit {
		return nil, errors.New("too large")
	}

	var payload HandshakePayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, err
	}

	if payload.Version != ProtocolVersion {
		return nil, fmt.Errorf("version: %s", payload.Version)
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

	// Check nonce for replay protection
	c.mu.Lock()
	if c.SeenNonces == nil {
		c.SeenNonces = make(map[int64]time.Time)
	}
	// Cleanup old nonces
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
	binary.Write(buf, binary.LittleEndian, payload.Timestamp)
	binary.Write(buf, binary.LittleEndian, payload.Nonce)
	buf.Write(payload.NaClPubKey)
	buf.Write(payload.EphemeralPub)

	ok, _ := remotePub.Verify(buf.Bytes(), payload.Signature)
	if !ok {
		return nil, errors.New("bad sig")
	}

	// Verify NaCl key matches stored key
	var recKey [32]byte
	copy(recKey[:], payload.NaClPubKey)
	if recKey != c.PublicKey {
		return nil, errors.New("key mismatch")
	}

	var ephPub [32]byte
	copy(ephPub[:], payload.EphemeralPub)
	return &ephPub, nil
}

// --- Fingerprint ---

// computeFingerprint generates human-readable key fingerprint
func computeFingerprint(pubKey []byte) string {
	hash := sha256.Sum256(pubKey)
	hex := fmt.Sprintf("%X", hash[:8])
	return fmt.Sprintf("%s-%s-%s-%s", hex[0:4], hex[4:8], hex[8:12], hex[12:16])
}
