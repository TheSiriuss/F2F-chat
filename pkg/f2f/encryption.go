package f2f

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// Параметры Argon2id
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // 64 MB
	argonThreads = 4
	argonKeyLen  = 32
	saltLen      = 16
)

var ErrWrongPassword = errors.New("wrong password or corrupted data")
var ErrNoPassword = errors.New("password required")

// deriveKey генерирует ключ из пароля используя Argon2id
func deriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
}

// encryptData шифрует данные с паролем используя XChaCha20-Poly1305
// Формат: salt (16) + nonce (24) + ciphertext
func encryptData(plaintext []byte, password string) ([]byte, error) {
	if password == "" {
		return nil, ErrNoPassword
	}

	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}

	key := deriveKey(password, salt)

	// XChaCha20-Poly1305
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plaintext)+aead.Overhead())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// Seal: добавляет ciphertext к nonce
	ciphertext := aead.Seal(nonce, nonce, plaintext, nil)

	// Result: salt + (nonce + ciphertext)
	result := make([]byte, saltLen+len(ciphertext))
	copy(result[:saltLen], salt)
	copy(result[saltLen:], ciphertext)

	return result, nil
}

// decryptData дешифрует данные
func decryptData(encrypted []byte, password string) ([]byte, error) {
	if password == "" {
		return nil, ErrNoPassword
	}

	// Проверка минимальной длины: Salt + Nonce + Tag
	if len(encrypted) < saltLen+24+16 {
		return nil, ErrWrongPassword
	}

	salt := encrypted[:saltLen]
	dataWithNonce := encrypted[saltLen:]

	key := deriveKey(password, salt)

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	if len(dataWithNonce) < aead.NonceSize() {
		return nil, ErrWrongPassword
	}

	nonce := dataWithNonce[:aead.NonceSize()]
	ciphertext := dataWithNonce[aead.NonceSize():]

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrWrongPassword
	}

	return plaintext, nil
}

// writeAtomic сохраняет данные атомарно: write -> sync -> close -> rename
func writeAtomic(filename string, data []byte) error {
	dir := filepath.Dir(filename)
	// Создаем временный файл в той же директории, чтобы Rename был атомарным
	tmpFile, err := os.CreateTemp(dir, "f2f-atomic-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	// Очистка в случае ошибки
	closed := false
	defer func() {
		if !closed {
			tmpFile.Close()
			os.Remove(tmpPath)
		}
	}()

	if _, err := tmpFile.Write(data); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}

	// Принудительный сброс на диск
	if err := tmpFile.Sync(); err != nil {
		return fmt.Errorf("sync temp file: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	closed = true

	// Атомарная замена
	if err := os.Rename(tmpPath, filename); err != nil {
		// Если Rename не удался, удаляем временный файл
		os.Remove(tmpPath)
		return fmt.Errorf("atomic rename: %w", err)
	}

	return nil
}

// saveEncrypted сохраняет данные в файл. Данные уже должны быть сериализованы в []byte.
func saveEncrypted(filename string, data []byte, password string) error {
	encrypted, err := encryptData(data, password)
	if err != nil {
		return err
	}

	return writeAtomic(filename, encrypted)
}

// loadEncrypted загружает и дешифрует данные из файла. Возвращает []byte, который caller должен десериализовать.
func loadEncrypted(filename string, password string) ([]byte, error) {
	encrypted, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	plaintext, err := decryptData(encrypted, password)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func IdentityExists() bool {
	_, err := os.Stat(IdentityFile)
	return err == nil
}

func ContactsExist() bool {
	_, err := os.Stat(ContactsFile)
	return err == nil
}

func ValidatePassword(password string) error {
	if !IdentityExists() {
		return nil
	}
	if password == "" {
		return ErrNoPassword
	}
	// Пытаемся расшифровать Identity, чтобы проверить пароль
	_, err := loadEncrypted(IdentityFile, password)
	return err
}

func IsNewUser() bool {
	return !IdentityExists()
}

func ChangePassword(oldPassword, newPassword string) error {
	if newPassword == "" {
		return ErrNoPassword
	}
	if err := ValidatePassword(oldPassword); err != nil {
		return err
	}

	// 1. Re-encrypt Identity
	if IdentityExists() {
		rawID, err := loadEncrypted(IdentityFile, oldPassword)
		if err != nil {
			return err
		}
		if err := saveEncrypted(IdentityFile, rawID, newPassword); err != nil {
			return err
		}
	}

	// 2. Re-encrypt Contacts
	if ContactsExist() {
		rawContacts, err := loadEncrypted(ContactsFile, oldPassword)
		if err != nil {
			return err
		}
		if err := saveEncrypted(ContactsFile, rawContacts, newPassword); err != nil {
			return err
		}
	}

	return nil
}
