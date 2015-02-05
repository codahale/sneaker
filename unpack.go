package sneaker

import (
	"bytes"
	"fmt"
	"io"

	"github.com/awslabs/aws-sdk-go/aws"
	"github.com/awslabs/aws-sdk-go/gen/kms"
)

// Unpack reads the packed secrets from the reader, decrypts the data key using
// KMS and the given context, decrypts the secrets, and returns an io.Reader
// containing a TAR file with all the secrets.
func (m *Manager) Unpack(ctxt map[string]string, r io.Reader) (io.Reader, error) {
	contents, err := Untar(r)
	if err != nil {
		return nil, err
	}

	keyCiphertext, ok := contents[keyFilename]
	if !ok {
		return nil, fmt.Errorf("%s not found", keyFilename)
	}

	ciphertext, ok := contents[tarFilename]
	if !ok {
		return nil, fmt.Errorf("%s not found", tarFilename)
	}

	key, err := m.Keys.Decrypt(&kms.DecryptRequest{
		CiphertextBlob:    keyCiphertext,
		EncryptionContext: ctxt,
	})
	if err != nil {
		if apiErr, ok := err.(aws.APIError); ok {
			if apiErr.Type == "InvalidCiphertextException" {
				return nil, fmt.Errorf("unable to decrypt data key")
			}
		}
		return nil, err
	}

	plaintext, err := decrypt(key.Plaintext, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to decrypt secrets")
	}

	return bytes.NewReader(plaintext), nil
}
