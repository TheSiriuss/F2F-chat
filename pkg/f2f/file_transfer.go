package f2f

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

// generateFileID создаёт уникальный ID для передачи файла
func generateFileID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// SendFile инициирует отправку файла (отправляет предложение)
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
		return errors.New("already have pending file transfer, wait or use .nofile to cancel")
	}

	// Проверяем файл
	info, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("cannot access file: %w", err)
	}
	if info.IsDir() {
		return errors.New("cannot send directory")
	}

	fileSize := info.Size()
	fileName := filepath.Base(filePath)
	fileID := generateFileID()

	// Создаём pending transfer
	transfer := &FileTransfer{
		ID:         fileID,
		Name:       fileName,
		Size:       fileSize,
		FilePath:   filePath,
		IsOutgoing: true,
		CreatedAt:  time.Now(),
	}

	c.mu.Lock()
	c.PendingFile = transfer
	c.mu.Unlock()

	// Отправляем предложение
	offer := FileOffer{
		ID:   fileID,
		Name: fileName,
		Size: fileSize,
	}
	offerJSON, _ := json.Marshal(offer)

	if err := n.sendSessionMessage(c, MsgTypeFileOffer, string(offerJSON)); err != nil {
		c.mu.Lock()
		c.PendingFile = nil
		c.mu.Unlock()
		return err
	}

	n.Log(LogLevelInfo, "Предложен файл '%s' (%s), ожидание ответа...", fileName, formatSize(fileSize))
	return nil
}

// AcceptFile принимает предложенный файл
func (n *Node) AcceptFile(nick string) error {
	c := n.getContactByNick(nick)
	if c == nil {
		// Если ник не указан, ищем в активном чате
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
		return errors.New("this is outgoing transfer, nothing to accept")
	}
	fileID := pending.ID
	fileName := pending.Name
	fileSize := pending.Size

	// Подготавливаем буфер
	pending.Buffer = make([]byte, 0, fileSize)
	c.mu.Unlock()

	// Отправляем accept
	resp := FileResponse{ID: fileID}
	respJSON, _ := json.Marshal(resp)

	if err := n.sendSessionMessage(c, MsgTypeFileAccept, string(respJSON)); err != nil {
		return err
	}

	n.Log(LogLevelSuccess, "Принят файл '%s' (%s), ожидание данных...", fileName, formatSize(fileSize))
	return nil
}

// DeclineFile отклоняет предложенный файл
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
	c.PendingFile = nil
	c.mu.Unlock()

	// Отправляем decline или cancel
	resp := FileResponse{ID: fileID}
	respJSON, _ := json.Marshal(resp)

	msgType := MsgTypeFileDecline
	if isOutgoing {
		msgType = MsgTypeFileCancel
	}

	n.sendSessionMessage(c, msgType, string(respJSON))

	if isOutgoing {
		n.Log(LogLevelInfo, "Отправка файла '%s' отменена", fileName)
	} else {
		n.Log(LogLevelInfo, "Файл '%s' отклонён", fileName)
	}
	return nil
}

// HasPendingFile проверяет есть ли pending файл у контакта в активном чате
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

// sendFileChunks отправляет файл чанками (вызывается после accept)
func (n *Node) sendFileChunks(c *Contact, transfer *FileTransfer) {
	// Читаем файл
	data, err := os.ReadFile(transfer.FilePath)
	if err != nil {
		n.listener.OnFileComplete(c.PeerID.String(), c.Nickname, transfer.Name, false, "read error: "+err.Error())
		c.mu.Lock()
		c.PendingFile = nil
		c.mu.Unlock()
		return
	}

	// Вычисляем хеш
	hash := sha256.Sum256(data)
	hashHex := hex.EncodeToString(hash[:])

	// Разбиваем на чанки
	totalChunks := (len(data) + FileChunkSize - 1) / FileChunkSize
	transfer.TotalChunks = totalChunks

	n.Log(LogLevelInfo, "Отправка '%s' (%d чанков)...", transfer.Name, totalChunks)

	for i := 0; i < totalChunks; i++ {
		// Проверяем отмену
		c.mu.Lock()
		if c.PendingFile == nil || c.PendingFile.Cancelled {
			c.mu.Unlock()
			return
		}
		c.mu.Unlock()

		start := i * FileChunkSize
		end := start + FileChunkSize
		if end > len(data) {
			end = len(data)
		}
		chunkData := data[start:end]

		chunk := FileChunk{
			ID:    transfer.ID,
			Index: i,
			Total: totalChunks,
			Data:  base64.StdEncoding.EncodeToString(chunkData),
		}
		chunkJSON, _ := json.Marshal(chunk)

		if err := n.sendSessionMessage(c, MsgTypeFileChunk, string(chunkJSON)); err != nil {
			n.listener.OnFileComplete(c.PeerID.String(), c.Nickname, transfer.Name, false, "send error")
			c.mu.Lock()
			c.PendingFile = nil
			c.mu.Unlock()
			return
		}

		// Прогресс
		progress := float64(i+1) / float64(totalChunks)
		n.listener.OnFileProgress(c.PeerID.String(), c.Nickname, transfer.Name, progress, true)
	}

	// Отправляем Done
	done := FileDone{
		ID:   transfer.ID,
		Hash: hashHex,
	}
	doneJSON, _ := json.Marshal(done)
	n.sendSessionMessage(c, MsgTypeFileDone, string(doneJSON))

	c.mu.Lock()
	c.PendingFile = nil
	c.mu.Unlock()

	n.listener.OnFileComplete(c.PeerID.String(), c.Nickname, transfer.Name, true, "sent")
	n.Log(LogLevelSuccess, "Файл '%s' отправлен!", transfer.Name)
}

// processFileOffer обрабатывает входящее предложение файла
func (n *Node) processFileOffer(c *Contact, body string) {
	var offer FileOffer
	if err := json.Unmarshal([]byte(body), &offer); err != nil {
		return
	}

	c.mu.Lock()
	// Если уже есть pending - автоматически отклоняем
	if c.PendingFile != nil {
		c.mu.Unlock()
		resp := FileResponse{ID: offer.ID}
		respJSON, _ := json.Marshal(resp)
		n.sendSessionMessage(c, MsgTypeFileDecline, string(respJSON))
		n.Log(LogLevelWarning, "Автоотклонён файл '%s' - уже есть активная передача", offer.Name)
		return
	}

	c.PendingFile = &FileTransfer{
		ID:         offer.ID,
		Name:       offer.Name,
		Size:       offer.Size,
		IsOutgoing: false,
		CreatedAt:  time.Now(),
	}
	c.mu.Unlock()

	n.listener.OnFileOffer(c.PeerID.String(), c.Nickname, offer.Name, offer.Size)
}

// processFileAccept обрабатывает принятие нашего файла
func (n *Node) processFileAccept(c *Contact, body string) {
	var resp FileResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		return
	}

	c.mu.Lock()
	pending := c.PendingFile
	if pending == nil || pending.ID != resp.ID || !pending.IsOutgoing {
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()

	// Запускаем отправку чанков
	go n.sendFileChunks(c, pending)
}

// processFileDecline обрабатывает отклонение файла
func (n *Node) processFileDecline(c *Contact, body string) {
	var resp FileResponse
	json.Unmarshal([]byte(body), &resp)

	c.mu.Lock()
	pending := c.PendingFile
	if pending == nil || pending.ID != resp.ID {
		c.mu.Unlock()
		return
	}
	fileName := pending.Name
	c.PendingFile = nil
	c.mu.Unlock()

	n.listener.OnFileComplete(c.PeerID.String(), c.Nickname, fileName, false, "declined")
	n.Log(LogLevelWarning, "%s отклонил файл '%s'", c.Nickname, fileName)
}

// processFileCancel обрабатывает отмену передачи
func (n *Node) processFileCancel(c *Contact, body string) {
	var resp FileResponse
	json.Unmarshal([]byte(body), &resp)

	c.mu.Lock()
	pending := c.PendingFile
	if pending == nil || pending.ID != resp.ID {
		c.mu.Unlock()
		return
	}
	fileName := pending.Name
	pending.Cancelled = true
	c.PendingFile = nil
	c.mu.Unlock()

	n.listener.OnFileComplete(c.PeerID.String(), c.Nickname, fileName, false, "cancelled")
	n.Log(LogLevelInfo, "%s отменил передачу '%s'", c.Nickname, fileName)
}

// processFileChunk обрабатывает чанк файла
func (n *Node) processFileChunk(c *Contact, body string) {
	var chunk FileChunk
	if err := json.Unmarshal([]byte(body), &chunk); err != nil {
		return
	}

	c.mu.Lock()
	pending := c.PendingFile
	if pending == nil || pending.ID != chunk.ID || pending.IsOutgoing {
		c.mu.Unlock()
		return
	}

	data, err := base64.StdEncoding.DecodeString(chunk.Data)
	if err != nil {
		c.mu.Unlock()
		return
	}

	pending.Buffer = append(pending.Buffer, data...)
	pending.Received += int64(len(data))
	pending.ChunksRecv = chunk.Index + 1
	pending.TotalChunks = chunk.Total

	progress := float64(pending.Received) / float64(pending.Size)
	fileName := pending.Name
	c.mu.Unlock()

	n.listener.OnFileProgress(c.PeerID.String(), c.Nickname, fileName, progress, false)
}

// processFileDone обрабатывает завершение передачи
func (n *Node) processFileDone(c *Contact, body string) {
	var done FileDone
	if err := json.Unmarshal([]byte(body), &done); err != nil {
		return
	}

	c.mu.Lock()
	pending := c.PendingFile
	if pending == nil || pending.ID != done.ID || pending.IsOutgoing {
		c.mu.Unlock()
		return
	}

	data := pending.Buffer
	fileName := pending.Name
	expectedHash := done.Hash
	c.PendingFile = nil
	c.mu.Unlock()

	// Проверяем хеш
	actualHash := sha256.Sum256(data)
	actualHashHex := hex.EncodeToString(actualHash[:])

	if actualHashHex != expectedHash {
		n.listener.OnFileComplete(c.PeerID.String(), c.Nickname, fileName, false, "hash mismatch - file corrupted")
		n.Log(LogLevelError, "Файл '%s' повреждён (хеш не совпадает)", fileName)
		return
	}

	// Сохраняем файл
	savePath := fileName
	// Избегаем перезаписи
	if _, err := os.Stat(savePath); err == nil {
		ext := filepath.Ext(fileName)
		base := fileName[:len(fileName)-len(ext)]
		savePath = fmt.Sprintf("%s_%s%s", base, time.Now().Format("150405"), ext)
	}

	if err := os.WriteFile(savePath, data, 0644); err != nil {
		n.listener.OnFileComplete(c.PeerID.String(), c.Nickname, fileName, false, "save error: "+err.Error())
		n.Log(LogLevelError, "Ошибка сохранения '%s': %v", fileName, err)
		return
	}

	n.listener.OnFileReceived(c.PeerID.String(), c.Nickname, fileName, savePath, int64(len(data)))
	n.Log(LogLevelSuccess, "Файл '%s' сохранён как '%s' (%s)", fileName, savePath, formatSize(int64(len(data))))
}

// formatSize форматирует размер файла
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
