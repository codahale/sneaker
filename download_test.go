package sneaker

import (
	"bytes"
	"io/ioutil"
	"reflect"
	"testing"

	"github.com/awslabs/aws-sdk-go/gen/kms"
	"github.com/awslabs/aws-sdk-go/gen/s3"
)

func TestDownload(t *testing.T) {
	key := make([]byte, 32)

	encryptedDataKey := []byte("woo hoo")
	encryptedSecret, err := encrypt(key, []byte("this is a secret"), nil)
	if err != nil {
		t.Fatal(err)
	}

	fakeS3 := &FakeS3{
		GetResponses: []s3.GetObjectOutput{
			{
				Body: ioutil.NopCloser(bytes.NewReader(encryptedSecret)),
			},
			{
				Body: ioutil.NopCloser(bytes.NewReader(encryptedDataKey)),
			},
		},
	}
	fakeKMS := &FakeKMS{
		DecryptResponses: []kms.DecryptResponse{
			{
				Plaintext: key,
			},
		},
	}

	man := Manager{
		Objects:           fakeS3,
		Keys:              fakeKMS,
		Bucket:            "bucket",
		Prefix:            "secrets",
		EncryptionContext: map[string]string{"A": "B"},
	}

	ctxt := map[string]string{
		"A":    "B",
		"Path": "s3://bucket/secrets/secret1.txt",
	}

	actual, err := man.Download([]string{"secret1.txt"})
	if err != nil {
		t.Fatal(err)
	}

	expected := map[string][]byte{
		"secret1.txt": []byte("this is a secret"),
	}

	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("Result was %#v, but expected %#v", actual, expected)
	}

	// AES get

	getReq := fakeS3.GetRequests[0]
	if v, want := *getReq.Bucket, "bucket"; v != want {
		t.Errorf("Bucket was %q, but expected %q", v, want)
	}

	if v, want := *getReq.Key, "secrets/secret1.txt.aes"; v != want {
		t.Errorf("Key was %q, but expected %q", v, want)
	}

	// KMS get

	getReq = fakeS3.GetRequests[1]
	if v, want := *getReq.Bucket, "bucket"; v != want {
		t.Errorf("Bucket was %q, but expected %q", v, want)
	}

	if v, want := *getReq.Key, "secrets/secret1.txt.kms"; v != want {
		t.Errorf("Key was %q, but expected %q", v, want)
	}

	// decrypt

	decReq := fakeKMS.DecryptRequests[0]
	if v := decReq.CiphertextBlob; !bytes.Equal(v, encryptedDataKey) {
		t.Errorf("CiphertextBlob was %x, but expected %x", v, encryptedDataKey)
	}

	if v := decReq.EncryptionContext; !reflect.DeepEqual(v, ctxt) {
		t.Errorf("EncryptionContext was %v, but expected %v", v, ctxt)
	}
}
