package sneaker

import (
	"fmt"
	"io/ioutil"
	fpath "path"

	"github.com/awslabs/aws-sdk-go/aws"
	"github.com/awslabs/aws-sdk-go/gen/kms"
	"github.com/awslabs/aws-sdk-go/gen/s3"
)

// Download fetches and decrypts the given secrets.
func (m *Manager) Download(paths []string) (map[string][]byte, error) {
	secrets := make(map[string][]byte, len(paths))
	for _, path := range paths {
		data, err := m.fetch(path + ".aes")
		if err != nil {
			return nil, err
		}

		key, err := m.fetch(path + ".kms")
		if err != nil {
			return nil, err
		}

		d, err := m.Keys.Decrypt(&kms.DecryptRequest{
			CiphertextBlob:    key,
			EncryptionContext: m.secretContext(fpath.Join(m.Prefix, path)),
		})
		if err != nil {
			if apiErr, ok := err.(aws.APIError); ok {
				if apiErr.Type == "InvalidCiphertextException" {
					return nil, fmt.Errorf("unable to decrypt data key")
				}
			}
			return nil, err
		}

		data, err = decrypt(d.Plaintext, data)
		if err != nil {
			return nil, fmt.Errorf("unable to decrypt secret")
		}

		secrets[path] = data
	}
	return secrets, nil
}

func (m *Manager) fetch(key string) ([]byte, error) {
	resp, err := m.Objects.GetObject(&s3.GetObjectRequest{
		Bucket: aws.String(m.Bucket),
		Key:    aws.String(fpath.Join(m.Prefix, key)),
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return ioutil.ReadAll(resp.Body)
}
