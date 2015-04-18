package sneaker

import (
	"bytes"
	"io/ioutil"
	"reflect"
	"testing"

	"github.com/awslabs/aws-sdk-go/aws"
	"github.com/awslabs/aws-sdk-go/service/kms"
	"github.com/awslabs/aws-sdk-go/service/s3"
)

func TestDownload(t *testing.T) {
	ciphertext := []byte{
		0x00, 0x00, 0x00, 0x0d, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65,
		0x64, 0x20, 0x6b, 0x65, 0x79, 0xba, 0xcf, 0x29, 0x4e, 0x6d, 0x09, 0x18,
		0x4e, 0x66, 0x6e, 0xb1, 0xb6, 0xc9, 0x87, 0x65, 0xcc, 0xe1, 0x06, 0x8c,
		0xbf, 0x7f, 0xdd, 0x5d, 0x70, 0x4e, 0x3d, 0xbf, 0xd5, 0x44, 0xec,
	}

	fakeS3 := &FakeS3{
		GetOutputs: []s3.GetObjectOutput{
			{
				Body: ioutil.NopCloser(bytes.NewReader(ciphertext)),
			},
		},
	}
	fakeKMS := &FakeKMS{
		DecryptOutputs: []kms.DecryptOutput{
			{
				KeyID:     aws.String("key1"),
				Plaintext: make([]byte, 32),
			},
		},
	}

	man := Manager{
		Objects: fakeS3,
		Envelope: Envelope{
			KMS: fakeKMS,
		},
		Bucket:            "bucket",
		Prefix:            "secrets",
		EncryptionContext: map[string]string{"A": "B"},
	}

	actual, err := man.Download([]string{"secret1.txt"})
	if err != nil {
		t.Fatal(err)
	}

	expected := map[string][]byte{
		"secret1.txt": []byte("this is a test"),
	}

	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("Result was %#v, but expected %#v", actual, expected)
	}

	getReq := fakeS3.GetInputs[0]
	if v, want := *getReq.Bucket, "bucket"; v != want {
		t.Errorf("Bucket was %q, but expected %q", v, want)
	}

	if v, want := *getReq.Key, "secrets/secret1.txt"; v != want {
		t.Errorf("Key was %q, but expected %q", v, want)
	}
}
