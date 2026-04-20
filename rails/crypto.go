package rails

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1" // #nosec
	"crypto/sha256"
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

// DeriveKey derives a 32-byte AES key from the secret key base using PBKDF2.
// hashName must be "sha1" or "sha256".
func DeriveKey(secretKeyBase, hashName string) ([]byte, error) {
	hashFunc, err := hashFuncByName(hashName)
	if err != nil {
		return nil, err
	}

	salt := "authenticated encrypted cookie"
	iterations := 1000
	keySize := 32

	return pbkdf2.Key([]byte(secretKeyBase), []byte(salt), iterations, keySize, hashFunc), nil
}

// Decrypt decrypts AES-256-GCM encrypted data.
func Decrypt(key, iv, encrypted, authTag []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	ciphertext := append(encrypted, authTag...)
	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// Encrypt encrypts plaintext with AES-256-GCM and returns iv, ciphertext, and auth tag.
func Encrypt(key, plaintext []byte) (iv, encrypted, authTag []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	iv = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	sealed := gcm.Seal(nil, iv, plaintext, nil)
	tagSize := gcm.Overhead()
	encrypted = sealed[:len(sealed)-tagSize]
	authTag = sealed[len(sealed)-tagSize:]

	return iv, encrypted, authTag, nil
}

func hashFuncByName(name string) (func() hash.Hash, error) {
	switch name {
	case "sha1":
		return sha1.New, nil
	case "sha256":
		return sha256.New, nil
	default:
		return nil, fmt.Errorf("unsupported hash function: %s (use sha1 or sha256)", name)
	}
}
