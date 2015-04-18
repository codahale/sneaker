package sneaker

import (
	"crypto/aes"
	"crypto/cipher"
)

// The encryption format used by sneaker is intentionally simple, with no
// versioning or algorithm agility. It uses AES-GCM with a randomly-generated
// 96-bit nonce. The nonce is prepended to the ciphertext.
//
// Should AES-GCM no longer be desirable in the future, we will simply begin
// encrypting using its replacement algorithm and only trying AES-GCM if a
// decryption is unsuccessful.

// encrypt encrypts the given plaintext and authenticates the given data using
// AES-GCM with the given key and an all-zero nonce. The key should be 128-,
// 196-, or 256-bits long.
//
// N.B.: THIS IS ONLY SAFE IF THE KEY IS A SINGLE-USE KEY.
func encrypt(key, plaintext, data []byte) ([]byte, error) {
	defer zero(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm.Seal(nil, nonce, plaintext, data), nil
}

// decrypt attempts to decrypt the given ciphertext and authenticate the given
// data using AES-GCM with the given key. The key should be 128-, 196-, or
// 256-bits long.
func decrypt(key, ciphertext, data []byte) ([]byte, error) {
	defer zero(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm.Open(nil, nonce, ciphertext, data)
}
