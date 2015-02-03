package sneaker

import (
	"archive/tar"
	"bytes"
	"io"
	"path/filepath"
	"time"

	"github.com/awslabs/aws-sdk-go/aws"
	"github.com/awslabs/aws-sdk-go/gen/kms"
)

// Pack encrypts the given secrets with a new data key from KMS with the given
// context, and writes a TAR archive containing both the encrypted data key and
// the encrypted TAR file to the given io.Writer.
func (m *Manager) Pack(secrets map[string][]byte, ctxt map[string]string, w io.Writer) error {
	key, err := m.Keys.GenerateDataKey(&kms.GenerateDataKeyRequest{
		EncryptionContext: ctxt,
		KeyID:             &m.KeyID,
		NumberOfBytes:     aws.Integer(32),
	})
	if err != nil {
		return err
	}

	buf := bytes.NewBuffer(nil)
	inner := tar.NewWriter(buf)
	for path, data := range secrets {
		if err := inner.WriteHeader(&tar.Header{
			Size:       int64(len(data)),
			Uname:      "root",
			Gname:      "root",
			Name:       filepath.Join(".", path),
			Mode:       0400,
			ModTime:    time.Now(),
			AccessTime: time.Now(),
			ChangeTime: time.Now(),
		}); err != nil {
			return err
		}

		if _, err := inner.Write(data); err != nil {
			return err
		}
	}

	if err := inner.Close(); err != nil {
		return err
	}

	enc, err := encrypt(key.Plaintext, buf.Bytes())
	if err != nil {
		return err
	}

	outer := tar.NewWriter(w)

	// write encrypted tar

	if err := outer.WriteHeader(&tar.Header{
		Size:       int64(len(enc)),
		Uname:      "root",
		Gname:      "root",
		Name:       tarFilename,
		Mode:       0400,
		ModTime:    time.Now(),
		AccessTime: time.Now(),
		ChangeTime: time.Now(),
	}); err != nil {
		return err
	}

	if _, err := outer.Write(enc); err != nil {
		return err
	}

	// write encrypted data key

	if err := outer.WriteHeader(&tar.Header{
		Size:       int64(len(key.CiphertextBlob)),
		Uname:      "root",
		Gname:      "root",
		Name:       keyFilename,
		Mode:       0400,
		ModTime:    time.Now(),
		AccessTime: time.Now(),
		ChangeTime: time.Now(),
	}); err != nil {
		return err
	}

	if _, err := outer.Write(key.CiphertextBlob); err != nil {
		return err
	}

	return outer.Close()
}

const (
	keyFilename = "key.kms"
	tarFilename = "encrypted.tar.aes"
)
