package sneaker

import (
	"archive/tar"
	"bytes"
	"io"
	"io/ioutil"
	"reflect"
	"testing"

	"github.com/awslabs/aws-sdk-go/gen/kms"
)

func TestPackagingRoundTrip(t *testing.T) {
	fakeKMS := &FakeKMS{
		GenerateResponses: []kms.GenerateDataKeyResponse{
			{
				Plaintext:      make([]byte, 32),
				CiphertextBlob: []byte("encrypted key"),
			},
		},
		DecryptResponses: []kms.DecryptResponse{
			{
				Plaintext: make([]byte, 32),
			},
		},
	}

	man := Manager{
		EncryptionContext: map[string]string{"A": "B"},
		Keys:              fakeKMS,
		KeyID:             "key1",
	}

	input := map[string][]byte{
		"example.txt": []byte("hello world"),
	}

	context := map[string]string{
		"hostname": "example.com",
	}

	buf := bytes.NewBuffer(nil)
	if err := man.Pack(input, context, "", buf); err != nil {
		t.Fatal(err)
	}

	r, err := man.Unpack(context, bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}

	output := map[string][]byte{}

	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}

		b, err := ioutil.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		output[hdr.Name] = b
	}

	if !reflect.DeepEqual(input, output) {
		t.Errorf("Input was %#v, but output was %#v", input, output)
	}

	genReq := fakeKMS.GenerateRequests[0]
	if v, want := *genReq.KeyID, "key1"; v != want {
		t.Errorf("Key ID was %q, but expected %q", v, want)
	}

	if v, want := *genReq.NumberOfBytes, 32; v != want {
		t.Errorf("Key size was %v, but expected %v", v, want)
	}

	if v, want := genReq.EncryptionContext, context; !reflect.DeepEqual(v, want) {
		t.Errorf("Encryption context was %#v, but expected %#v", v, want)
	}

	decReq := fakeKMS.DecryptRequests[0]
	if v, want := decReq.CiphertextBlob, []byte("encrypted key"); !bytes.Equal(v, want) {
		t.Errorf("Ciphertext Blob was %v, but expected %v", v, want)
	}

	if v, want := decReq.EncryptionContext, context; !reflect.DeepEqual(v, want) {
		t.Errorf("Encryption context was %#v, but expected %#v", v, want)
	}
}
