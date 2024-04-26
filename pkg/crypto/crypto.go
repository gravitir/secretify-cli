package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"strings"
)

// GenerateEncryptionKeyString generates a random encryption key of length 32.
func GenerateEncryptionKeyString() ([]byte, error) {
	// Choose the key length (256 bits for AES-256)
	keyLength := 32

	// Generate random bytes for the key
	key := make([]byte, keyLength)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}

	return key, nil // Return the raw key bytes
}

// EncryptDataMap encrypts each value in the given map using AES encryption.
func EncryptDataMap(dataMap map[string]string, key []byte) (map[string]string, error) {
	m := make(map[string]string)

	for k, v := range dataMap {
		encryptedValue, err := EncryptStringToDataURL(v, key)
		if err != nil {
			return nil, err
		}
		m[k] = encryptedValue
	}
	return m, nil
}

// EncryptString encrypts a plaintext string using AES encryption.
func EncryptString(plaintext string, key []byte) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := aesGCM.Seal(nil, nonce, []byte(plaintext), nil)

	// Combine nonce and ciphertext and encode as base64
	encrypted := append(nonce, ciphertext...)
	return base64.RawStdEncoding.EncodeToString(encrypted), nil
}

// EncryptStringToDataURL encrypts a plaintext string and returns it as a data URL.
func EncryptStringToDataURL(plaintext string, key []byte) (string, error) {
	// Encrypt the plaintext
	encryptedBase64, err := EncryptString(plaintext, key)
	if err != nil {
		return "", err
	}

	// Create the data URL
	dataURL := "data:application/octet-stream;base64," + encryptedBase64
	return dataURL, nil
}

// DecryptString decrypts a ciphertext string using the provided key.
func DecryptString(ciphertext string, key []byte) (string, error) {

	decoded, err := base64.RawStdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	if len(decoded) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertextBytes := decoded[:nonceSize], decoded[nonceSize:]

	plaintext, err := aesGCM.Open(nil, nonce, []byte(ciphertextBytes), nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// DecryptStringFromDataURL decrypts a ciphertext string encoded as a data URL using the provided key.
func DecryptStringFromDataURL(ciphertext string, key []byte) (string, error) {
	ciphertext = strings.Replace(ciphertext, "data:application/octet-stream;base64,", "", 1)

	// Decrypt the cipher
	plaintext, err := DecryptString(ciphertext, key)
	if err != nil {
		return "", err
	}

	return plaintext, nil
}
