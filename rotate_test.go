package sneaker

import (
	"bytes"
	"io/ioutil"
	"testing"
	"time"

	"github.com/awslabs/aws-sdk-go/aws"
	"github.com/awslabs/aws-sdk-go/service/kms"
	"github.com/awslabs/aws-sdk-go/service/s3"
)

func TestRotate(t *testing.T) {
	oldKey := func() []byte {
		return make([]byte, 32)
	}

	newKey := func() []byte {
		k := oldKey()
		k[0] = 100
		return k
	}

	oldCiphertext := []byte{
		0x00, 0x00, 0x00, 0x0d, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65,
		0x64, 0x20, 0x6b, 0x65, 0x79, 0xba, 0xcf, 0x29, 0x4e, 0x6d, 0x09, 0x18,
		0x4e, 0x66, 0x6e, 0xb1, 0xb6, 0xc9, 0x87, 0x65, 0xcc, 0xe1, 0x06, 0x8c,
		0xbf, 0x7f, 0xdd, 0x5d, 0x70, 0x4e, 0x3d, 0xbf, 0xd5, 0x44, 0xec,
	}

	fakeS3 := &FakeS3{
		ListOutputs: []s3.ListObjectsOutput{
			{
				Contents: []*s3.Object{
					{
						Key:          aws.String("secrets/weeble.txt"),
						ETag:         aws.String(`"etag1"`),
						Size:         aws.Long(1004),
						LastModified: aws.Time(time.Date(2006, 1, 2, 15, 4, 5, 0, time.UTC)),
					},
				},
			},
		},
		GetOutputs: []s3.GetObjectOutput{
			{
				Body: ioutil.NopCloser(bytes.NewReader(oldCiphertext)),
			},
		},
		PutOutputs: []s3.PutObjectOutput{
			{},
			{},
		},
	}
	fakeKMS := &FakeKMS{
		DecryptOutputs: []kms.DecryptOutput{
			{
				KeyID:     aws.String("key1"),
				Plaintext: oldKey(),
			},
		},
		GenerateOutputs: []kms.GenerateDataKeyOutput{
			{
				CiphertextBlob: []byte("encrypted new key"),
				KeyID:          aws.String("key1"),
				Plaintext:      newKey(),
			},
		},
	}

	man := Manager{
		Objects: fakeS3,
		Envelope: Envelope{
			KMS: fakeKMS,
		},
		KeyID:  "key1",
		Bucket: "bucket",
		Prefix: "secrets",
	}

	if err := man.Rotate("", nil); err != nil {
		t.Fatal(err)
	}

	// KMS request

	genReq := fakeKMS.GenerateInputs[0]
	if v, want := *genReq.KeyID, "key1"; v != want {
		t.Errorf("Key ID was %q, but expected %q", v, want)
	}

	if v, want := *genReq.NumberOfBytes, int64(32); v != want {
		t.Errorf("Key size was %d, but expected %d", v, want)
	}

	putReq := fakeS3.PutInputs[0]
	if v, want := *putReq.Bucket, "bucket"; v != want {
		t.Errorf("Bucket was %q, but expected %q", v, want)
	}

	if v, want := *putReq.Key, "secrets/weeble.txt"; v != want {
		t.Errorf("Key was %q, but expected %q", v, want)
	}

	if v, want := *putReq.ContentLength, int64(51); v != want {
		t.Errorf("ContentLength was %d, but expected %d", v, want)
	}

	if v, want := *putReq.ContentType, "application/octet-stream"; v != want {
		t.Errorf("ContentType was %q, but expected %q", v, want)
	}

	actual, err := ioutil.ReadAll(putReq.Body)
	if err != nil {
		t.Fatal(err)
	}

	expected := []byte{
		0x00, 0x00, 0x00, 0x11, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65,
		0x64, 0x20, 0x6e, 0x65, 0x77, 0x20, 0x6b, 0x65, 0x79, 0xf2, 0x9a, 0x57,
		0x34, 0x4c, 0xd7, 0x31, 0x48, 0xd9, 0xdb, 0x85, 0x49, 0x98, 0x2e, 0x95,
		0x30, 0x9f, 0x00, 0x7a, 0x91, 0x85, 0x8e, 0x2d, 0x26, 0x0a, 0x5f, 0x2e,
		0x0d, 0xf9, 0xa2,
	}

	if !bytes.Equal(actual, expected) {
		t.Errorf("Was %x but expected %x", actual, expected)
	}
}
