package services

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
)

type CryptoService struct {
	key []byte
}

func NewCryptoService(secret string) *CryptoService {
	// Derive a 32-byte key from the secret using SHA-256
	hash := sha256.Sum256([]byte(secret))
	return &CryptoService{key: hash[:]}
}

// Encrypt encrypts plaintext using AES-256-GCM
func (c *CryptoService) Encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}

	block, err := aes.NewCipher(c.key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts ciphertext that was encrypted with Encrypt
func (c *CryptoService) Decrypt(ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}

	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(c.key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, encryptedData := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// EncryptPtr encrypts a pointer string (handles nil)
func (c *CryptoService) EncryptPtr(plaintext *string) (*string, error) {
	if plaintext == nil {
		return nil, nil
	}
	result, err := c.Encrypt(*plaintext)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// DecryptPtr decrypts a pointer string (handles nil)
func (c *CryptoService) DecryptPtr(ciphertext *string) (*string, error) {
	if ciphertext == nil {
		return nil, nil
	}
	result, err := c.Decrypt(*ciphertext)
	if err != nil {
		return nil, err
	}
	return &result, nil
}
