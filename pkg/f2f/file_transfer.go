package f2f

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

	// Создаём временный файл для записи
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

	// Отправляем accept
	resp := FileResponse{ID: fileID}
	respJSON, _ := json.Marshal(resp)

	if err := n.sendSessionMessage(c, MsgTypeFileAccept, string(respJSON)); err != nil {
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

	// Закрываем temp файл если есть
	if pending.TempFile != nil {
		pending.TempFile.Close()
		os.Remove(pending.TempPath)
	}
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

// HasPendingFile проверяет есть ли pending файл
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

// sendFileChunks отправляет файл чанками (потоково, без загрузки в память)
func (n *Node) sendFileChunks(c *Contact, transfer *FileTransfer) {
	// Открываем файл для чтения
	file, err := os.Open(transfer.FilePath)
	if err != nil {
		n.listener.OnFileComplete(c.PeerID.String(), c.Nickname, transfer.Name, false, "open error: "+err.Error())
		c.mu.Lock()
		c.PendingFile = nil
		c.mu.Unlock()
		return
	}
	defer file.Close()

	// Hasher для вычисления хеша по ходу чтения
	hasher := sha256.New()

	// Разбиваем на чанки
	totalChunks := int((transfer.Size + FileChunkSize - 1) / FileChunkSize)
	transfer.TotalChunks = totalChunks

	n.Log(LogLevelInfo, "Отправка '%s' (%d чанков)...", transfer.Name, totalChunks)

	// Буфер для одного чанка (переиспользуем)
	chunkBuffer := make([]byte, FileChunkSize)

	for i := 0; i < totalChunks; i++ {
		// Проверяем отмену
		c.mu.Lock()
		if c.PendingFile == nil || c.PendingFile.Cancelled {
			c.mu.Unlock()
			return
		}
		c.mu.Unlock()

		// Читаем чанк из файла
		bytesRead, err := file.Read(chunkBuffer)
		if err != nil && err != io.EOF {
			n.listener.OnFileComplete(c.PeerID.String(), c.Nickname, transfer.Name, false, "read error: "+err.Error())
			c.mu.Lock()
			c.PendingFile = nil
			c.mu.Unlock()
			return
		}

		if bytesRead == 0 {
			break
		}

		chunkData := chunkBuffer[:bytesRead]

		// Обновляем хеш
		hasher.Write(chunkData)

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

	// Отправляем Done с хешем
	hashHex := hex.EncodeToString(hasher.Sum(nil))
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

	// Закрываем temp файл
	if pending.TempFile != nil {
		pending.TempFile.Close()
		os.Remove(pending.TempPath)
	}
	c.PendingFile = nil
	c.mu.Unlock()

	n.listener.OnFileComplete(c.PeerID.String(), c.Nickname, fileName, false, "cancelled")
	n.Log(LogLevelInfo, "%s отменил передачу '%s'", c.Nickname, fileName)
}

// processFileChunk обрабатывает чанк файла (пишет сразу на диск)
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

	// Проверяем что temp файл открыт
	if pending.TempFile == nil {
		c.mu.Unlock()
		return
	}

	data, err := base64.StdEncoding.DecodeString(chunk.Data)
	if err != nil {
		c.mu.Unlock()
		return
	}

	// Пишем чанк на диск
	_, err = pending.TempFile.Write(data)
	if err != nil {
		c.mu.Unlock()
		n.Log(LogLevelError, "Ошибка записи файла: %v", err)
		return
	}

	// Обновляем хеш
	if pending.Hasher != nil {
		pending.Hasher.Write(data)
	}

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

	fileName := pending.Name
	tempPath := pending.TempPath
	expectedHash := done.Hash
	var actualHashHex string

	// Получаем хеш
	if pending.Hasher != nil {
		actualHashHex = hex.EncodeToString(pending.Hasher.Sum(nil))
	}

	// Закрываем temp файл
	if pending.TempFile != nil {
		pending.TempFile.Close()
	}

	c.PendingFile = nil
	c.mu.Unlock()

	// Проверяем хеш
	if actualHashHex != expectedHash {
		os.Remove(tempPath)
		n.listener.OnFileComplete(c.PeerID.String(), c.Nickname, fileName, false, "hash mismatch - file corrupted")
		n.Log(LogLevelError, "Файл '%s' повреждён (хеш не совпадает)", fileName)
		return
	}

	// Определяем финальный путь
	savePath := fileName
	if _, err := os.Stat(savePath); err == nil {
		ext := filepath.Ext(fileName)
		base := fileName[:len(fileName)-len(ext)]
		savePath = fmt.Sprintf("%s_%s%s", base, time.Now().Format("150405"), ext)
	}

	// Переименовываем temp -> final
	if err := os.Rename(tempPath, savePath); err != nil {
		// Если переименование не работает (разные диски), копируем
		if err := copyFile(tempPath, savePath); err != nil {
			os.Remove(tempPath)
			n.listener.OnFileComplete(c.PeerID.String(), c.Nickname, fileName, false, "save error: "+err.Error())
			n.Log(LogLevelError, "Ошибка сохранения '%s': %v", fileName, err)
			return
		}
		os.Remove(tempPath)
	}

	// Получаем размер сохранённого файла
	info, _ := os.Stat(savePath)
	savedSize := info.Size()

	n.listener.OnFileReceived(c.PeerID.String(), c.Nickname, fileName, savePath, savedSize)
	n.Log(LogLevelSuccess, "Файл '%s' сохранён как '%s' (%s)", fileName, savePath, formatSize(savedSize))
}

// copyFile копирует файл (fallback если rename не работает)
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
