// Package secman provides an integrated system for security storing sensitive
// information using Amazon's Simple Storage Service (S3) and Key Management
// Service (KMS).
package secman

import (
	"time"

	"github.com/awslabs/aws-sdk-go/gen/kms"
	"github.com/awslabs/aws-sdk-go/gen/s3"
)

// ObjectStorage is a sub-set of the capabilities of the S3 client.
type ObjectStorage interface {
	ListObjects(*s3.ListObjectsRequest) (*s3.ListObjectsOutput, error)
	DeleteObject(*s3.DeleteObjectRequest) (*s3.DeleteObjectOutput, error)
	PutObject(*s3.PutObjectRequest) (*s3.PutObjectOutput, error)
}

// KeyManagement is a sub-set of the capabilities of the KMS client.
type KeyManagement interface {
	GenerateDataKey(*kms.GenerateDataKeyRequest) (*kms.GenerateDataKeyResponse, error)
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
	Objects        ObjectStorage
	Keys           KeyManagement
	KeyID          string
	Bucket, Prefix string
}
