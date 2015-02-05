package sneaker

import (
	"bytes"
	"io/ioutil"
	"testing"
	"time"

	"github.com/awslabs/aws-sdk-go/aws"
	"github.com/awslabs/aws-sdk-go/gen/kms"
	"github.com/awslabs/aws-sdk-go/gen/s3"
)

func TestRotate(t *testing.T) {
	oldKey := make([]byte, 32)
	newKey := make([]byte, 32)
	newKey[0] = 100

	encryptedDataKey := []byte("encrypted old key")
	encryptedSecret, err := encrypt(oldKey, []byte("this is a secret"), nil)
	if err != nil {
		t.Fatal(err)
	}

	fakeS3 := &FakeS3{
		ListResponses: []s3.ListObjectsOutput{
			{
				Contents: []s3.Object{
					{
						Key:          aws.String("secrets/weeble.txt.aes"),
						ETag:         aws.String(`"etag1"`),
						Size:         aws.Long(1004),
						LastModified: time.Date(2006, 1, 2, 15, 4, 5, 0, time.UTC),
					},
				},
			},
		},
		GetResponses: []s3.GetObjectOutput{
			{
				Body: ioutil.NopCloser(bytes.NewReader(encryptedSecret)),
			},
			{
				Body: ioutil.NopCloser(bytes.NewReader(encryptedDataKey)),
			},
		},
		PutResponses: []s3.PutObjectOutput{
			{},
			{},
		},
	}
	fakeKMS := &FakeKMS{
		DecryptResponses: []kms.DecryptResponse{
			{
				Plaintext: oldKey,
			},
		},
		GenerateResponses: []kms.GenerateDataKeyResponse{
			{
				Plaintext:      newKey,
				CiphertextBlob: []byte("encrypted new key"),
			},
		},
	}

	man := Manager{
		Objects: fakeS3,
		Keys:    fakeKMS,
		KeyID:   "key1",
		Bucket:  "bucket",
		Prefix:  "secrets",
	}

	if err := man.Rotate("", nil); err != nil {
		t.Fatal(err)
	}

	// KMS request

	genReq := fakeKMS.GenerateRequests[0]
	if v, want := *genReq.KeyID, "key1"; v != want {
		t.Errorf("Key ID was %q, but expected %q", v, want)
	}

	if v, want := *genReq.NumberOfBytes, 32; v != want {
		t.Errorf("Key size was %d, but expected %d", v, want)
	}

	// key upload

	putReq := fakeS3.PutRequests[0]
	if v, want := *putReq.Bucket, "bucket"; v != want {
		t.Errorf("Bucket was %q, but expected %q", v, want)
	}

	if v, want := *putReq.Key, "secrets/weeble.txt.kms"; v != want {
		t.Errorf("Key was %q, but expected %q", v, want)
	}

	if v, want := *putReq.ContentLength, int64(17); v != want {
		t.Errorf("ContentLength was %d, but expected %d", v, want)
	}

	if v, want := *putReq.ContentType, "application/octet-stream"; v != want {
		t.Errorf("ContentType was %q, but expected %q", v, want)
	}

	encDataKey, err := ioutil.ReadAll(putReq.Body)
	if err != nil {
		t.Fatal(err)
	}

	if v, want := string(encDataKey), "encrypted new key"; v != want {
		t.Errorf("Encrypted key was %q, but expected %q", v, want)
	}

	// secret upload

	putReq = fakeS3.PutRequests[1]
	if v, want := *putReq.Bucket, "bucket"; v != want {
		t.Errorf("Bucket was %q, but expected %q", v, want)
	}

	if v, want := *putReq.Key, "secrets/weeble.txt.aes"; v != want {
		t.Errorf("Key was %q, but expected %q", v, want)
	}

	if v, want := *putReq.ContentLength, int64(44); v != want {
		t.Errorf("ContentLength was %d, but expected %d", v, want)
	}

	if v, want := *putReq.ContentType, "application/octet-stream"; v != want {
		t.Errorf("ContentType was %q, but expected %q", v, want)
	}

	encSecret, err := ioutil.ReadAll(putReq.Body)
	if err != nil {
		t.Fatal(err)
	}

	secret, err := decrypt(newKey, encSecret, nil)
	if err != nil {
		t.Fatal(err)
	}

	if v, want := string(secret), "this is a secret"; v != want {
		t.Errorf("Decrypted secret was %q, but expected %q", v, want)
	}
}
