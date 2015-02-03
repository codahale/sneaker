package sneaker

import (
	"archive/tar"
	"bytes"
	"io"
	"io/ioutil"

	"github.com/awslabs/aws-sdk-go/gen/kms"
)

// Unpack reads the packed secrets from the reader, decrypts the data key using
// KMS and the given context, decrypts the secrets, and returns an io.Reader
// containing a TAR file with all the secrets.
func (m *Manager) Unpack(ctxt map[string]string, r io.Reader) (io.Reader, error) {
	var encKey, encTar []byte

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
			encTar = buf
		}
	}

	key, err := m.Keys.Decrypt(&kms.DecryptRequest{
		CiphertextBlob:    encKey,
		EncryptionContext: ctxt,
	})
	if err != nil {
		return nil, err
	}

	decTar, err := decrypt(key.Plaintext, encTar)
	if err != nil {
		return nil, err
	}

	return bytes.NewReader(decTar), nil
}
