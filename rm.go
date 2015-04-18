package sneaker

import (
	fpath "path"

	"github.com/awslabs/aws-sdk-go/aws"
	"github.com/awslabs/aws-sdk-go/service/s3"
)

// Rm deletes the given secret.
func (m *Manager) Rm(path string) error {
	_, err := m.Objects.DeleteObject(&s3.DeleteObjectInput{
		Bucket: aws.String(m.Bucket),
		Key:    aws.String(fpath.Join(m.Prefix, path)),
	})
	return err
}
