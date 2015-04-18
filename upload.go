package sneaker

import (
	"bytes"
	"io"
	"io/ioutil"
	fpath "path"

	"github.com/awslabs/aws-sdk-go/aws"
	"github.com/awslabs/aws-sdk-go/service/kms"
	"github.com/awslabs/aws-sdk-go/service/s3"
)

// Upload encrypts the given secret with a KMS data key and uploads it to S3.
func (m *Manager) Upload(path string, r io.Reader) error {
	path = fpath.Join(m.Prefix, path)

	plaintext, err := ioutil.ReadAll(r)
	if err != nil {
		return err
	}

	key, err := m.Keys.GenerateDataKey(&kms.GenerateDataKeyInput{
		EncryptionContext: m.secretContext(path),
		KeyID:             &m.KeyID,
		NumberOfBytes:     aws.Long(32),
	})
	if err != nil {
		return err
	}

	ciphertext, err := encrypt(key.Plaintext, plaintext, []byte(*key.KeyID))
	if err != nil {
		return err
	}

	if _, err := m.Objects.PutObject(
		&s3.PutObjectInput{
			ContentLength: aws.Long(int64(len(key.CiphertextBlob))),
			ContentType:   aws.String(kmsContentType),
			Bucket:        aws.String(m.Bucket),
			Key:           aws.String(path + kmsExt),
			Body:          bytes.NewReader(key.CiphertextBlob),
		},
	); err != nil {
		return err
	}

	if _, err := m.Objects.PutObject(
		&s3.PutObjectInput{
			ContentLength: aws.Long(int64(len(ciphertext))),
			ContentType:   aws.String(aesContentType),
			Bucket:        aws.String(m.Bucket),
			Key:           aws.String(path + aesExt),
			Body:          bytes.NewReader(ciphertext),
		},
	); err != nil {
		return err
	}
	return nil
}
