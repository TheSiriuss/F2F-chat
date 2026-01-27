package f2f

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

func generateFileID() ([16]byte, string) {
	var id [16]byte
	rand.Read(id[:])
	return id, hex.EncodeToString(id[:])
}

func parseFileID(hexStr string) ([16]byte, error) {
	var id [16]byte
	b, err := hex.DecodeString(hexStr)
	if err != nil || len(b) != 16 {
		return id, errors.New("invalid file ID")
	}
	copy(id[:], b)
	return id, nil
}

func (n *Node) SendFile(peerID peer.ID, filePath string) error {
	c := n.getContactByID(peerID)
	if c == nil {
		return errors.New("contact not found")
	}

	c.mu.Lock()
	state := c.State
	hasPending := c.PendingFile != nil
	c.mu.Unlock()

	if state != StateActive {
		return errors.New("chat not active")
	}

	if hasPending {
		return errors.New("already have pending file transfer")
	}

	info, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("cannot access file: %w", err)
	}
	if info.IsDir() {
		return errors.New("cannot send directory")
	}
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("cannot read file: %w", err)
	}
	f.Close()

	fileSize := info.Size()
	fileName := filepath.Base(filePath)
	fileIDBinary, fileIDHex := generateFileID()

	transfer := &FileTransfer{
		ID:         fileIDHex,
		IDBinary:   fileIDBinary,
		Name:       fileName,
		Size:       fileSize,
		FilePath:   filePath,
		IsOutgoing: true,
		CreatedAt:  time.Now(),
	}

	c.mu.Lock()
	c.PendingFile = transfer
	c.mu.Unlock()

	offer := FileOffer{
		ID:   fileIDHex,
		Name: fileName,
		Size: fileSize,
	}

	if err := n.sendSessionMessage(c, MsgTypeFileOffer, offer.Marshal()); err != nil {
		c.mu.Lock()
		c.PendingFile = nil
		c.mu.Unlock()
		return err
	}

	n.Log(LogLevelInfo, "Предложен файл '%s' (%s), ожидание ответа...", fileName, formatSize(fileSize))
	return nil
}

func (n *Node) AcceptFile(nick string) error {
	c := n.getContactByNick(nick)
	if c == nil {
		activeID := n.GetActiveChat()
		if activeID == "" {
			return errors.New("no active chat")
		}
		c = n.getContactByID(activeID)
		if c == nil {
			return errors.New("contact not found")
		}
	}

	c.mu.Lock()
	pending := c.PendingFile
	if pending == nil {
		c.mu.Unlock()
		return errors.New("no pending file offer")
	}
	if pending.IsOutgoing {
		c.mu.Unlock()
		return errors.New("this is outgoing transfer")
	}
	fileID := pending.ID
	fileName := pending.Name

	tempPath := fileName + ".tmp." + fileID[:8]
	tempFile, err := os.Create(tempPath)
	if err != nil {
		c.mu.Unlock()
		return fmt.Errorf("cannot create temp file: %w", err)
	}

	pending.TempFile = tempFile
	pending.TempPath = tempPath
	pending.Hasher = sha256.New()
	c.mu.Unlock()

	resp := FileResponse{ID: fileID}

	if err := n.sendSessionMessage(c, MsgTypeFileAccept, resp.Marshal()); err != nil {
		tempFile.Close()
		os.Remove(tempPath)
		c.mu.Lock()
		c.PendingFile = nil
		c.mu.Unlock()
		return err
	}

	n.Log(LogLevelSuccess, "Принят файл '%s' (%s), ожидание данных...", fileName, formatSize(pending.Size))
	return nil
}

func (n *Node) DeclineFile(nick string) error {
	c := n.getContactByNick(nick)
	if c == nil {
		activeID := n.GetActiveChat()
		if activeID == "" {
			return errors.New("no active chat")
		}
		c = n.getContactByID(activeID)
		if c == nil {
			return errors.New("contact not found")
		}
	}

	c.mu.Lock()
	pending := c.PendingFile
	if pending == nil {
		c.mu.Unlock()
		return errors.New("no pending file transfer")
	}
	fileID := pending.ID
	fileName := pending.Name
	isOutgoing := pending.IsOutgoing

	if pending.TempFile != nil {
		pending.TempFile.Close()
		os.Remove(pending.TempPath)
	}
	c.PendingFile = nil
	c.mu.Unlock()

	resp := FileResponse{ID: fileID}
	payload := resp.Marshal()

	msgType := MsgTypeFileDecline
	if isOutgoing {
		msgType = MsgTypeFileCancel
	}

	n.sendSessionMessage(c, msgType, payload)

	if isOutgoing {
		n.Log(LogLevelInfo, "Отправка файла '%s' отменена", fileName)
	} else {
		n.Log(LogLevelInfo, "Файл '%s' отклонён", fileName)
	}
	return nil
}

func (n *Node) HasPendingFile() (bool, bool, string, int64) {
	activeID := n.GetActiveChat()
	if activeID == "" {
		return false, false, "", 0
	}
	c := n.getContactByID(activeID)
	if c == nil {
		return false, false, "", 0
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.PendingFile == nil {
		return false, false, "", 0
	}
	return true, c.PendingFile.IsOutgoing, c.PendingFile.Name, c.PendingFile.Size
}

func (n *Node) sendFileChunks(c *Contact, transfer *FileTransfer) {
	c.mu.Lock()
	// FIX: Используем Ratchet вместо sessionKey
	hasRatchet := c.Ratchet != nil
	nick := c.Nickname
	pid := c.PeerID
	c.mu.Unlock()

	if !hasRatchet {
		n.notifyFileComplete(pid.String(), nick, transfer.Name, false, "no session")
		c.mu.Lock()
		c.PendingFile = nil
		c.mu.Unlock()
		return
	}

	file, err := os.Open(transfer.FilePath)
	if err != nil {
		n.notifyFileComplete(pid.String(), nick, transfer.Name, false, "open error: "+err.Error())
		c.mu.Lock()
		c.PendingFile = nil
		c.mu.Unlock()
		return
	}
	defer file.Close()

	hasher := sha256.New()
	totalChunks := int((transfer.Size + FileChunkSize - 1) / FileChunkSize)
	transfer.TotalChunks = totalChunks

	n.Log(LogLevelInfo, "Отправка '%s' (%d чанков, Double Ratchet)...", transfer.Name, totalChunks)

	chunkBuffer := make([]byte, FileChunkSize)

	for i := 0; i < totalChunks; i++ {
		c.mu.Lock()
		if c.PendingFile == nil || c.PendingFile.Cancelled {
			c.mu.Unlock()
			return
		}
		c.mu.Unlock()

		bytesRead, err := file.Read(chunkBuffer)
		if err != nil && err != io.EOF {
			n.notifyFileComplete(pid.String(), nick, transfer.Name, false, "read error: "+err.Error())
			c.mu.Lock()
			c.PendingFile = nil
			c.mu.Unlock()
			return
		}

		if bytesRead == 0 {
			break
		}

		chunkData := chunkBuffer[:bytesRead]
		hasher.Write(chunkData)

		// FIX: Убрали аргумент sessionKey
		if err := n.sendBinaryChunk(c, transfer.IDBinary, uint32(i), uint32(totalChunks), chunkData); err != nil {
			n.notifyFileComplete(pid.String(), nick, transfer.Name, false, "send error")
			c.mu.Lock()
			c.PendingFile = nil
			c.mu.Unlock()
			return
		}

		progress := float64(i+1) / float64(totalChunks)
		n.notifyFileProgress(pid.String(), nick, transfer.Name, progress, true)
	}

	hashHex := hex.EncodeToString(hasher.Sum(nil))
	done := FileDone{
		ID:   transfer.ID,
		Hash: hashHex,
	}

	n.sendSessionMessage(c, MsgTypeFileDone, done.Marshal())

	c.mu.Lock()
	c.PendingFile = nil
	c.mu.Unlock()

	n.notifyFileComplete(pid.String(), nick, transfer.Name, true, "sent")
	n.Log(LogLevelSuccess, "Файл '%s' отправлен!", transfer.Name)
}

// FIX: Новая сигнатура, принимает расшифрованный plaintext
func (n *Node) processBinaryChunk(c *Contact, plaintext []byte) {
	// Дешифровка уже выполнена в readLoop через RatchetDecrypt
	if len(plaintext) < BinaryChunkHeaderSize {
		return
	}

	// Читаем заголовок прямо из plaintext
	// [FileID 16] [Index 4] [Total 4] [Data...]
	var fileID [16]byte
	copy(fileID[:], plaintext[0:16])
	// Используем encoding/binary из пакета binary (нужно проверить импорты, но в этом файле он не импортирован)
	// Добавим ручное чтение BigEndian, так как binary не импортирован в оригинале,
	// но лучше добавить import "encoding/binary" в начало файла.
	// (Я добавил "encoding/binary" в импорты types.go, но не здесь. Здесь нет import "encoding/binary")
	// Предполагаем, что нужно добавить импорт. Для надежности реализуем тут.

	// Helper for uint32
	beUint32 := func(b []byte) uint32 {
		return uint32(b[3]) | uint32(b[2])<<8 | uint32(b[1])<<16 | uint32(b[0])<<24
	}

	index := beUint32(plaintext[16:20])
	total := beUint32(plaintext[20:24])
	data := plaintext[24:]

	c.mu.Lock()
	pending := c.PendingFile
	if pending == nil || pending.IDBinary != fileID || pending.IsOutgoing {
		c.mu.Unlock()
		return
	}

	if pending.TempFile == nil {
		c.mu.Unlock()
		return
	}

	newSize := pending.Received + int64(len(data))
	if newSize > pending.Size {
		c.mu.Unlock()
		n.Log(LogLevelError, "Ошибка: overflow")
		c.mu.Lock()
		if pending.TempFile != nil {
			pending.TempFile.Close()
			os.Remove(pending.TempPath)
		}
		c.PendingFile = nil
		c.mu.Unlock()
		n.notifyFileComplete(c.PeerID.String(), c.Nickname, pending.Name, false, "size overflow")
		return
	}

	_, err := pending.TempFile.Write(data)
	if err != nil {
		c.mu.Unlock()
		n.Log(LogLevelError, "Ошибка записи: %v", err)
		return
	}

	if pending.Hasher != nil {
		pending.Hasher.Write(data)
	}

	pending.Received = newSize
	pending.ChunksRecv = int(index) + 1
	pending.TotalChunks = int(total)

	progress := float64(pending.Received) / float64(pending.Size)
	fileName := pending.Name
	nick := c.Nickname
	pid := c.PeerID
	c.mu.Unlock()

	n.notifyFileProgress(pid.String(), nick, fileName, progress, false)
}

func (n *Node) processFileOffer(c *Contact, payload []byte) {
	var offer FileOffer
	if err := offer.Unmarshal(payload); err != nil {
		return
	}

	fileIDBinary, err := parseFileID(offer.ID)
	if err != nil {
		return
	}

	c.mu.Lock()
	if c.PendingFile != nil {
		c.mu.Unlock()
		resp := FileResponse{ID: offer.ID}
		n.sendSessionMessage(c, MsgTypeFileDecline, resp.Marshal())
		n.Log(LogLevelWarning, "Автоотклонён файл '%s' - занято", offer.Name)
		return
	}

	nick := c.Nickname
	pid := c.PeerID
	safeName := filepath.Base(offer.Name)

	c.PendingFile = &FileTransfer{
		ID:         offer.ID,
		IDBinary:   fileIDBinary,
		Name:       safeName,
		Size:       offer.Size,
		IsOutgoing: false,
		CreatedAt:  time.Now(),
	}
	c.mu.Unlock()

	n.notifyFileOffer(pid.String(), nick, safeName, offer.Size)
}

func (n *Node) processFileAccept(c *Contact, payload []byte) {
	var resp FileResponse
	if err := resp.Unmarshal(payload); err != nil {
		return
	}

	c.mu.Lock()
	pending := c.PendingFile
	if pending == nil || pending.ID != resp.ID || !pending.IsOutgoing {
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()

	go n.sendFileChunks(c, pending)
}

func (n *Node) processFileDecline(c *Contact, payload []byte) {
	var resp FileResponse
	if err := resp.Unmarshal(payload); err != nil {
		return
	}

	c.mu.Lock()
	pending := c.PendingFile
	if pending == nil || pending.ID != resp.ID {
		c.mu.Unlock()
		return
	}
	fileName := pending.Name
	nick := c.Nickname
	pid := c.PeerID
	c.PendingFile = nil
	c.mu.Unlock()

	n.notifyFileComplete(pid.String(), nick, fileName, false, "declined")
	n.Log(LogLevelWarning, "%s отклонил файл '%s'", nick, fileName)
}

func (n *Node) processFileCancel(c *Contact, payload []byte) {
	var resp FileResponse
	if err := resp.Unmarshal(payload); err != nil {
		return
	}

	c.mu.Lock()
	pending := c.PendingFile
	if pending == nil || pending.ID != resp.ID {
		c.mu.Unlock()
		return
	}
	fileName := pending.Name
	nick := c.Nickname
	pid := c.PeerID
	pending.Cancelled = true

	if pending.TempFile != nil {
		pending.TempFile.Close()
		os.Remove(pending.TempPath)
	}
	c.PendingFile = nil
	c.mu.Unlock()

	n.notifyFileComplete(pid.String(), nick, fileName, false, "cancelled")
	n.Log(LogLevelInfo, "%s отменил передачу '%s'", nick, fileName)
}

func (n *Node) processFileDone(c *Contact, payload []byte) {
	var done FileDone
	if err := done.Unmarshal(payload); err != nil {
		return
	}

	c.mu.Lock()
	pending := c.PendingFile
	if pending == nil || pending.ID != done.ID || pending.IsOutgoing {
		c.mu.Unlock()
		return
	}

	fileName := pending.Name
	tempPath := pending.TempPath
	expectedHash := done.Hash
	nick := c.Nickname
	pid := c.PeerID
	var actualHashHex string

	if pending.Hasher != nil {
		actualHashHex = hex.EncodeToString(pending.Hasher.Sum(nil))
	}

	if pending.TempFile != nil {
		pending.TempFile.Close()
	}

	c.PendingFile = nil
	c.mu.Unlock()

	if actualHashHex != expectedHash {
		os.Remove(tempPath)
		n.notifyFileComplete(pid.String(), nick, fileName, false, "hash mismatch")
		n.Log(LogLevelError, "Файл '%s' повреждён", fileName)
		return
	}

	savePath := fileName
	if _, err := os.Stat(savePath); err == nil {
		ext := filepath.Ext(fileName)
		base := fileName[:len(fileName)-len(ext)]
		savePath = fmt.Sprintf("%s_%s%s", base, time.Now().Format("150405"), ext)
	}

	if err := os.Rename(tempPath, savePath); err != nil {
		if err := copyFile(tempPath, savePath); err != nil {
			os.Remove(tempPath)
			n.notifyFileComplete(pid.String(), nick, fileName, false, "save error")
			return
		}
		os.Remove(tempPath)
	}

	info, _ := os.Stat(savePath)
	savedSize := info.Size()

	n.notifyFileReceived(pid.String(), nick, fileName, savePath, savedSize)
	n.Log(LogLevelSuccess, "Файл '%s' сохранён как '%s' (%s)", fileName, savePath, formatSize(savedSize))
}

func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	return err
}

func formatSize(bytes int64) string {
	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
	)
	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.2f GB", float64(bytes)/GB)
	case bytes >= MB:
		return fmt.Sprintf("%.2f MB", float64(bytes)/MB)
	case bytes >= KB:
		return fmt.Sprintf("%.2f KB", float64(bytes)/KB)
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}
