package sneaker

import (
	"bytes"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/awslabs/aws-sdk-go/aws"
	"github.com/awslabs/aws-sdk-go/service/kms"
	"github.com/awslabs/aws-sdk-go/service/s3"
)

func TestUpload(t *testing.T) {
	fakeKMS := &FakeKMS{
		GenerateOutputs: []kms.GenerateDataKeyOutput{
			{
				CiphertextBlob: []byte("encrypted key"),
				KeyID:          aws.String("key1"),
				Plaintext:      make([]byte, 32),
			},
		},
	}

	fakeS3 := &FakeS3{
		PutOutputs: []s3.PutObjectOutput{
			{},
			{},
		},
	}

	man := Manager{
		Objects: fakeS3,
		Envelope: Envelope{
			KMS: fakeKMS,
		},
		KeyID:             "key1",
		EncryptionContext: map[string]string{"A": "B"},
		Bucket:            "bucket",
		Prefix:            "secrets",
	}

	if err := man.Upload("weeble.txt", strings.NewReader("this is a test")); err != nil {
		t.Fatal(err)
	}

	putReq := fakeS3.PutInputs[0]
	if v, want := *putReq.Bucket, "bucket"; v != want {
		t.Errorf("Bucket was %q, but expected %q", v, want)
	}

	if v, want := *putReq.Key, "secrets/weeble.txt"; v != want {
		t.Errorf("Key was %q, but expected %q", v, want)
	}

	if v, want := *putReq.ContentLength, int64(47); v != want {
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
		0x00, 0x00, 0x00, 0x0d, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65,
		0x64, 0x20, 0x6b, 0x65, 0x79, 0xba, 0xcf, 0x29, 0x4e, 0x6d, 0x09, 0x18,
		0x4e, 0x66, 0x6e, 0xb1, 0xb6, 0xc9, 0x87, 0x65, 0xcc, 0xe1, 0x06, 0x8c,
		0xbf, 0x7f, 0xdd, 0x5d, 0x70, 0x4e, 0x3d, 0xbf, 0xd5, 0x44, 0xec,
	}

	if !bytes.Equal(actual, expected) {
		t.Errorf("Was %x but expected %x", actual, expected)
	}
}
