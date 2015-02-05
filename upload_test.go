package sneaker

import (
	"io/ioutil"
	"reflect"
	"strings"
	"testing"

	"github.com/awslabs/aws-sdk-go/aws"
	"github.com/awslabs/aws-sdk-go/gen/kms"
	"github.com/awslabs/aws-sdk-go/gen/s3"
)

func TestUpload(t *testing.T) {
	fakeKMS := &FakeKMS{
		GenerateResponses: []kms.GenerateDataKeyResponse{
			{
				CiphertextBlob: []byte("encrypted key"),
				KeyID:          aws.String("key1"),
				Plaintext:      make([]byte, 32),
			},
		},
	}

	fakeS3 := &FakeS3{
		PutResponses: []s3.PutObjectOutput{
			{},
			{},
		},
	}

	man := Manager{
		Objects:           fakeS3,
		Keys:              fakeKMS,
		Bucket:            "bucket",
		Prefix:            "secrets",
		EncryptionContext: map[string]string{"A": "B"},
		KeyID:             "key1",
	}

	ctxt := map[string]string{
		"A":    "B",
		"Path": "s3://bucket/secrets/weeble.txt",
	}

	if err := man.Upload("weeble.txt", strings.NewReader("this is a test")); err != nil {
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

	if v := genReq.EncryptionContext; !reflect.DeepEqual(v, ctxt) {
		t.Errorf("EncryptionContext was %v, but expected %v", v, ctxt)
	}

	// key upload

	putReq := fakeS3.PutRequests[0]
	if v, want := *putReq.Bucket, "bucket"; v != want {
		t.Errorf("Bucket was %q, but expected %q", v, want)
	}

	if v, want := *putReq.Key, "secrets/weeble.txt.kms"; v != want {
		t.Errorf("Key was %q, but expected %q", v, want)
	}

	if v, want := *putReq.ContentLength, int64(13); v != want {
		t.Errorf("ContentLength was %d, but expected %d", v, want)
	}

	if v, want := *putReq.ContentType, "application/octet-stream"; v != want {
		t.Errorf("ContentType was %q, but expected %q", v, want)
	}

	encDataKey, err := ioutil.ReadAll(putReq.Body)
	if err != nil {
		t.Fatal(err)
	}

	if v, want := string(encDataKey), "encrypted key"; v != want {
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

	if v, want := *putReq.ContentLength, int64(42); v != want {
		t.Errorf("ContentLength was %d, but expected %d", v, want)
	}

	if v, want := *putReq.ContentType, "application/octet-stream"; v != want {
		t.Errorf("ContentType was %q, but expected %q", v, want)
	}

	encSecret, err := ioutil.ReadAll(putReq.Body)
	if err != nil {
		t.Fatal(err)
	}

	secret, err := decrypt(make([]byte, 32), encSecret, []byte("key1"))
	if err != nil {
		t.Fatal(err)
	}

	if v, want := string(secret), "this is a test"; v != want {
		t.Errorf("Decrypted secret was %q, but expected %q", v, want)
	}
}
