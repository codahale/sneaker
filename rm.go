package secman

import (
	fpath "path"

	"github.com/awslabs/aws-sdk-go/aws"
	"github.com/awslabs/aws-sdk-go/gen/s3"
)

// Rm deletes the given secret and its encrypted data key.
func (m *Manager) Rm(path string) error {
	if _, err := m.Objects.DeleteObject(&s3.DeleteObjectRequest{
		Bucket: aws.String(m.Bucket),
		Key:    aws.String(fpath.Join(m.Prefix, path+".kms")),
	}); err != nil {
		return err
	}

	if _, err := m.Objects.DeleteObject(&s3.DeleteObjectRequest{
		Bucket: aws.String(m.Bucket),
		Key:    aws.String(fpath.Join(m.Prefix, path+".aes")),
	}); err != nil {
		return err
	}
	return nil
}
