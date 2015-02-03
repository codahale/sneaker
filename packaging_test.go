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
		Keys:  fakeKMS,
		KeyID: "key1",
	}

	input := map[string][]byte{
		"example.txt": []byte("hello world"),
	}

	buf := bytes.NewBuffer(nil)
	if err := man.Pack(input, buf); err != nil {
		t.Fatal(err)
	}

	r, err := man.Unpack(bytes.NewReader(buf.Bytes()))
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
}
