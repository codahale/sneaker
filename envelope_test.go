package sneaker

import (
	"bytes"
	"testing"

	"github.com/awslabs/aws-sdk-go/aws"
	"github.com/awslabs/aws-sdk-go/service/kms"
)

func TestEnvelopeSeal(t *testing.T) {
	fakeKMS := &FakeKMS{
		GenerateOutputs: []kms.GenerateDataKeyOutput{
			{
				CiphertextBlob: []byte("yay"),
				KeyID:          aws.String("key1"),
				Plaintext:      make([]byte, 32),
			},
		},
	}

	envelope := Envelope{
		KMS:            fakeKMS,
		KeyID:          "yay",
		DefaultContext: map[string]string{"A": "B"},
	}

	ciphertext, err := envelope.Seal("a/b/c/", []byte("this is the plaintext"))
	if err != nil {
		t.Fatal(err)
	}

	expected := []byte{
		0x00, 0x00, 0x00, 0x03, 0x79, 0x61, 0x79, 0xba, 0xcf, 0x29, 0x4e, 0x6d,
		0x09, 0x18, 0x4e, 0x73, 0x26, 0xa0, 0xf3, 0xca, 0x9f, 0xfc, 0x71, 0x1c,
		0x14, 0x66, 0xb2, 0x43, 0xe1, 0x1e, 0x20, 0x63, 0x9c, 0x16, 0x52, 0x37,
		0x76, 0xc2, 0x92, 0x2d, 0xb2, 0x26, 0xa4, 0xbd,
	}

	if !bytes.Equal(ciphertext, expected) {
		t.Errorf("Was %x but expected %x", ciphertext, expected)
	}
}

func TestEnvelopeOpen(t *testing.T) {
	ciphertext := []byte{
		0x00, 0x00, 0x00, 0x03, 0x79, 0x61, 0x79, 0xba, 0xcf, 0x29, 0x4e, 0x6d,
		0x09, 0x18, 0x4e, 0x73, 0x26, 0xa0, 0xf3, 0xca, 0x9f, 0xfc, 0x71, 0x1c,
		0x14, 0x66, 0xb2, 0x43, 0xe1, 0x1e, 0x20, 0x63, 0x9c, 0x16, 0x52, 0x37,
		0x76, 0xc2, 0x92, 0x2d, 0xb2, 0x26, 0xa4, 0xbd,
	}

	fakeKMS := &FakeKMS{
		DecryptOutputs: []kms.DecryptOutput{
			{
				KeyID:     aws.String("key1"),
				Plaintext: make([]byte, 32),
			},
		},
	}

	envelope := Envelope{
		KMS:            fakeKMS,
		KeyID:          "yay",
		DefaultContext: map[string]string{"A": "B"},
	}

	plaintext, err := envelope.Open("a/b/c/", ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	expected := []byte("this is the plaintext")
	if !bytes.Equal(plaintext, expected) {
		t.Errorf("Was %x but expected %x", plaintext, expected)
	}
}
