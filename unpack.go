package sneaker

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/awslabs/aws-sdk-go/aws"
	"github.com/awslabs/aws-sdk-go/gen/kms"
)

// Unpack reads the packed secrets from the reader, decrypts the data key using
// KMS and the given context, decrypts the secrets, and returns an io.Reader
// containing a TAR file with all the secrets.
func (m *Manager) Unpack(ctxt map[string]string, r io.Reader) (io.Reader, error) {
	var encKey, ciphertext []byte

	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break // end of tar archive
		} else if err != nil {
			return nil, err
		}

		if hdr.Name == keyFilename {
			buf, err := ioutil.ReadAll(tr)
			if err != nil {
				return nil, err
			}
			encKey = buf
		} else if hdr.Name == tarFilename {
			buf, err := ioutil.ReadAll(tr)
			if err != nil {
				return nil, err
			}
			ciphertext = buf
		}
	}

	key, err := m.Keys.Decrypt(&kms.DecryptRequest{
		CiphertextBlob:    encKey,
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
