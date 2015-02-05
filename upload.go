package sneaker

import (
	"bytes"
	"io"
	"io/ioutil"
	fpath "path"

	"github.com/awslabs/aws-sdk-go/aws"
	"github.com/awslabs/aws-sdk-go/gen/kms"
	"github.com/awslabs/aws-sdk-go/gen/s3"
)

// Upload encrypts the given secret with a KMS data key and uploads it to S3.
func (m *Manager) Upload(path string, r io.Reader) error {
	path = fpath.Join(m.Prefix, path)

	plaintext, err := ioutil.ReadAll(r)
	if err != nil {
		return err
	}

	key, err := m.Keys.GenerateDataKey(&kms.GenerateDataKeyRequest{
		EncryptionContext: m.secretContext(path),
		KeyID:             &m.KeyID,
		NumberOfBytes:     aws.Integer(32),
	})
	if err != nil {
		return err
	}

	ciphertext, err := encrypt(key.Plaintext, plaintext, nil)
	if err != nil {
		return err
	}

	if _, err := m.Objects.PutObject(
		&s3.PutObjectRequest{
			ContentLength: aws.Long(int64(len(key.CiphertextBlob))),
			ContentType:   aws.String(contentType),
			Bucket:        aws.String(m.Bucket),
			Key:           aws.String(path + ".kms"),
			Body:          ioutil.NopCloser(bytes.NewReader(key.CiphertextBlob)),
		},
	); err != nil {
		return err
	}

	if _, err := m.Objects.PutObject(
		&s3.PutObjectRequest{
			ContentLength: aws.Long(int64(len(ciphertext))),
			ContentType:   aws.String(contentType),
			Bucket:        aws.String(m.Bucket),
			Key:           aws.String(path + ".aes"),
			Body:          ioutil.NopCloser(bytes.NewReader(ciphertext)),
		},
	); err != nil {
		return err
	}
	return nil
}

const contentType = "application/octet-stream"
