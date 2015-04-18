package sneaker

import (
	"archive/tar"
	"bytes"
	"io"
	fpath "path"
	"time"
)

// Pack encrypts the given secrets with a new data key from KMS with the given
// context, and writes a TAR archive containing both the encrypted data key and
// the encrypted TAR file to the given io.Writer.
func (m *Manager) Pack(secrets map[string][]byte, ctxt map[string]string, keyID string, w io.Writer) error {
	if keyID == "" {
		keyID = m.KeyID
	}

	buf := bytes.NewBuffer(nil)
	tw := tar.NewWriter(buf)
	for path, data := range secrets {
		if err := tw.WriteHeader(&tar.Header{
			Size:       int64(len(data)),
			Uname:      "root",
			Gname:      "root",
			Name:       fpath.Join(".", path),
			Mode:       0400,
			ModTime:    time.Now(),
			AccessTime: time.Now(),
			ChangeTime: time.Now(),
		}); err != nil {
			return err
		}

		if _, err := tw.Write(data); err != nil {
			return err
		}
	}

	if err := tw.Close(); err != nil {
		return err
	}

	ciphertext, err := m.Envelope.Seal(keyID, ctxt, buf.Bytes())
	if err != nil {
		return err
	}

	_, err = w.Write(ciphertext)
	return err
}
