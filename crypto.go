package sneaker

// The encryption format used by sneaker is intentionally simple, with no
// versioning or algorithm agility. It uses AES-GCM with a randomly-generated
// 96-bit nonce. The nonce is prepended to the ciphertext.
//
// Should AES-GCM no longer be desirable in the future, we will simply begin
// encrypting using its replacement algorithm and only trying AES-GCM if a
// decryption is unsuccessful.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

// encrypt encrypts the given data with the given key using AES-GCM and a random
// nonce, which is prepended to the ciphertext. The key should be 128-, 196-, or
// 256-bits long.
func encrypt(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

// decrypt attempts to decrypt the given ciphertext with the given key using
// AES-GCM. The key should be 128-, 196-, or 256-bits long.
func decrypt(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(data) <= gcm.NonceSize()+gcm.Overhead() {
		return nil, errors.New("cipher: message authentication failed")
	}

	nonce := data[:gcm.NonceSize()]
	ciphertext := data[gcm.NonceSize():]

	return gcm.Open(nil, nonce, ciphertext, nil)
}
