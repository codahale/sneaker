// Package sneaker provides an integrated system for securely storing sensitive
// information using Amazon's Simple Storage Service (S3) and Key Management
// Service (KMS).
package sneaker

import (
	"archive/tar"
	"fmt"
	"io"
	"io/ioutil"
	"time"

	"github.com/awslabs/aws-sdk-go/aws"
	"github.com/awslabs/aws-sdk-go/service/kms"
	"github.com/awslabs/aws-sdk-go/service/s3"
)

// ObjectStorage is a sub-set of the capabilities of the S3 client.
type ObjectStorage interface {
	ListObjects(*s3.ListObjectsInput) (*s3.ListObjectsOutput, error)
	DeleteObject(*s3.DeleteObjectInput) (*s3.DeleteObjectOutput, error)
	PutObject(*s3.PutObjectInput) (*s3.PutObjectOutput, error)
	GetObject(*s3.GetObjectInput) (*s3.GetObjectOutput, error)
}

// KeyManagement is a sub-set of the capabilities of the KMS client.
type KeyManagement interface {
	GenerateDataKey(*kms.GenerateDataKeyInput) (*kms.GenerateDataKeyOutput, error)
	Decrypt(*kms.DecryptInput) (*kms.DecryptOutput, error)
}

// A File is an encrypted secret, stored in S3.
type File struct {
	Path         string
	LastModified time.Time
	Size         int
	ETag         string
}

// A Manager allows you to manage files.
type Manager struct {
	Objects           ObjectStorage
	Keys              KeyManagement
	KeyID             string
	Bucket, Prefix    string
	EncryptionContext *map[string]*string
}

func (m *Manager) secretContext(path string) *map[string]*string {
	ctxt := make(map[string]*string)
	if m.EncryptionContext != nil {
		for k, v := range *m.EncryptionContext {
			ctxt[k] = v
		}
	}
	ctxt["Path"] = aws.String(fmt.Sprintf("s3://%s/%s", m.Bucket, path))
	return &ctxt
}

// Untar parses the contents of the given reader as a TAR archive and returns a
// map of file names to file contents.
func Untar(r io.Reader) (map[string][]byte, error) {
	contents := map[string][]byte{}
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break // end of tar archive
		} else if err != nil {
			return nil, err
		}

		buf, err := ioutil.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		contents[hdr.Name] = buf
	}
	return contents, nil
}

const (
	aesExt = ".aes"
	kmsExt = ".kms"

	aesContentType = "application/octet-stream"
	kmsContentType = "application/octet-stream"

	keyFilename = "key" + kmsExt
	tarFilename = "secrets.tar" + aesExt
)
