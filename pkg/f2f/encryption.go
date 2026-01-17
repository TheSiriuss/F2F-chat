package f2f

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/argon2"
)

// Параметры Argon2id
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // 64 MB
	argonThreads = 4
	argonKeyLen  = 32
	saltLen      = 16
	nonceLen     = 12 // для AES-GCM
)

// ErrWrongPassword возвращается при неверном пароле
var ErrWrongPassword = errors.New("wrong password or corrupted data")

// ErrNoPassword возвращается когда пароль пустой
var ErrNoPassword = errors.New("password required")

// deriveKey генерирует ключ из пароля используя Argon2id
func deriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
}

// encryptData шифрует данные с паролем
// Формат: salt (16) + nonce (12) + ciphertext
func encryptData(plaintext []byte, password string) ([]byte, error) {
	if password == "" {
		return nil, ErrNoPassword
	}

	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}

	key := deriveKey(password, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}

	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	result := make([]byte, saltLen+nonceLen+len(ciphertext))
	copy(result[:saltLen], salt)
	copy(result[saltLen:saltLen+nonceLen], nonce)
	copy(result[saltLen+nonceLen:], ciphertext)

	return result, nil
}

// decryptData дешифрует данные с паролем
func decryptData(encrypted []byte, password string) ([]byte, error) {
	if password == "" {
		return nil, ErrNoPassword
	}

	minLen := saltLen + nonceLen + 16 // минимум для GCM tag
	if len(encrypted) < minLen {
		return nil, ErrWrongPassword
	}

	salt := encrypted[:saltLen]
	nonce := encrypted[saltLen : saltLen+nonceLen]
	ciphertext := encrypted[saltLen+nonceLen:]

	key := deriveKey(password, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrWrongPassword
	}

	return plaintext, nil
}

// saveEncrypted сохраняет зашифрованные данные в файл
func saveEncrypted(filename string, data any, password string) error {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	encrypted, err := encryptData(jsonData, password)
	if err != nil {
		return err
	}

	return os.WriteFile(filename, encrypted, 0600)
}

// loadEncrypted загружает и дешифрует данные из файла
func loadEncrypted(filename string, dest any, password string) error {
	encrypted, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	plaintext, err := decryptData(encrypted, password)
	if err != nil {
		return err
	}

	return json.Unmarshal(plaintext, dest)
}

// IdentityExists проверяет существует ли файл identity
func IdentityExists() bool {
	_, err := os.Stat(IdentityFile)
	return err == nil
}

// ContactsExist проверяет существует ли файл контактов
func ContactsExist() bool {
	_, err := os.Stat(ContactsFile)
	return err == nil
}

// ValidatePassword проверяет пароль попыткой дешифровки identity
func ValidatePassword(password string) error {
	if !IdentityExists() {
		return nil // Новый пользователь, любой пароль валиден
	}

	if password == "" {
		return ErrNoPassword
	}

	var id LocalIdentity
	return loadEncrypted(IdentityFile, &id, password)
}

// IsNewUser проверяет, новый ли это пользователь (нет identity файла)
func IsNewUser() bool {
	return !IdentityExists()
}

// ChangePassword меняет пароль (перешифровывает все файлы)
func ChangePassword(oldPassword, newPassword string) error {
	if newPassword == "" {
		return ErrNoPassword
	}

	// Проверяем старый пароль
	if err := ValidatePassword(oldPassword); err != nil {
		return err
	}

	// Загружаем identity
	var identity LocalIdentity
	if IdentityExists() {
		if err := loadEncrypted(IdentityFile, &identity, oldPassword); err != nil {
			return fmt.Errorf("load identity: %w", err)
		}
		// Сохраняем с новым паролем
		if err := saveEncrypted(IdentityFile, identity, newPassword); err != nil {
			return fmt.Errorf("save identity: %w", err)
		}
	}

	// Загружаем контакты
	if ContactsExist() {
		var contacts []Contact
		if err := loadEncrypted(ContactsFile, &contacts, oldPassword); err != nil {
			return fmt.Errorf("load contacts: %w", err)
		}
		// Сохраняем с новым паролем
		if err := saveEncrypted(ContactsFile, contacts, newPassword); err != nil {
			return fmt.Errorf("save contacts: %w", err)
		}
	}

	return nil
}
