package sneaker

import (
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
		Objects:           fakeS3,
		Keys:              fakeKMS,
		Bucket:            "bucket",
		Prefix:            "secrets",
		EncryptionContext: &map[string]*string{"A": aws.String("B")},
		KeyID:             "key1",
	}

	ctxt := map[string]*string{
		"A":    aws.String("B"),
		"Path": aws.String("s3://bucket/secrets/weeble.txt"),
	}

	if err := man.Upload("weeble.txt", strings.NewReader("this is a test")); err != nil {
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

	for name, a := range *genReq.EncryptionContext {
		b := ctxt[name]
		if *a != *b {
			t.Errorf("EncryptionContext[%v] was %v, but expected %v", name, *a, *b)
		}
	}

	// key upload

	putReq := fakeS3.PutInputs[0]
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

	putReq = fakeS3.PutInputs[1]
	if v, want := *putReq.Bucket, "bucket"; v != want {
		t.Errorf("Bucket was %q, but expected %q", v, want)
	}

	if v, want := *putReq.Key, "secrets/weeble.txt.aes"; v != want {
		t.Errorf("Key was %q, but expected %q", v, want)
	}

	if v, want := *putReq.ContentLength, int64(30); v != want {
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
