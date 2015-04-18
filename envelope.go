package sneaker

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"

	"github.com/awslabs/aws-sdk-go/aws"
	"github.com/awslabs/aws-sdk-go/service/kms"
)

// An Envelope encrypts and decrypts secrets with single-use KMS data keys using
// AES-256-GCM.
type Envelope struct {
	KMS KeyManagement
}

// Seal generates a 256-bit data key using KMS and encrypts the given plaintext
// with AES-256-GCM using a fixed, all-zero nonce. That ciphertext is appended
// to the ciphertext of the KMS data key and returned.
//
// The KMS data key's encryption context consists of the Envelope's default
// context plus the given path, if any.
func (e *Envelope) Seal(keyID string, ctxt map[string]string, plaintext []byte) ([]byte, error) {
	key, err := e.KMS.GenerateDataKey(&kms.GenerateDataKeyInput{
		EncryptionContext: e.context(ctxt),
		KeyID:             &keyID,
		NumberOfBytes:     aws.Long(keySize),
	})
	if err != nil {
		return nil, err
	}
	defer zero(key.Plaintext)

	block, err := aes.NewCipher(key.Plaintext)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, []byte(*key.KeyID))

	return join(key.CiphertextBlob, ciphertext), nil
}

// Open takes the output of Seal and decrypts it. If any part of the ciphertext,
// context, or path is modified, Seal will return an error instead of the
// decrypted data.
func (e *Envelope) Open(ctxt map[string]string, ciphertext []byte) ([]byte, error) {
	key, ciphertext := split(ciphertext)

	d, err := e.KMS.Decrypt(&kms.DecryptInput{
		CiphertextBlob:    key,
		EncryptionContext: e.context(ctxt),
	})
	if err != nil {
		if apiErr, ok := err.(aws.APIError); ok {
			if apiErr.Code == "InvalidCiphertextException" {
				return nil, fmt.Errorf("unable to decrypt data key")
			}
		}
		return nil, err
	}
	defer zero(d.Plaintext)

	block, err := aes.NewCipher(d.Plaintext)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm.Open(nil, nonce, ciphertext, []byte(*d.KeyID))
}

func (e *Envelope) context(c map[string]string) *map[string]*string {
	ctxt := make(map[string]*string)
	for k, v := range c {
		ctxt[k] = aws.String(v)
	}
	return &ctxt
}

func join(a, b []byte) []byte {
	res := make([]byte, len(a)+len(b)+4)
	binary.BigEndian.PutUint32(res, uint32(len(a)))
	copy(res[4:], a)
	copy(res[len(a)+4:], b)
	return res
}

func split(v []byte) ([]byte, []byte) {
	l := binary.BigEndian.Uint32(v)
	return v[4 : 4+l], v[4+l:]
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

var (
	nonce = make([]byte, 12)
)

const keySize = 32
