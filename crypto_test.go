package sneaker

import (
	"bytes"
	"testing"
)

func TestZerosKeyAfterUse(t *testing.T) {
	key1 := []byte("ayellowsubmarine")
	key2 := []byte("ayellowsubmarine")
	plaintext := []byte("hello this is Stripe")

	ciphertext, _ := encrypt(key1, plaintext, nil)
	if !bytes.Equal(key1, make([]byte, len(key1))) {
		t.Errorf("Key was not zeroed")
	}

	_, _ = decrypt(key2, ciphertext, nil)
	if !bytes.Equal(key2, make([]byte, len(key2))) {
		t.Errorf("Key was not zeroed")
	}
}

func TestGCMRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	input := []byte("hello this is Stripe")

	enc, err := encrypt(key, input, []byte("yay"))
	if err != nil {
		t.Fatal(err)
	}

	dec, err := decrypt(key, enc, []byte("yay"))
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(input, dec) {
		t.Errorf("Was %x, but expected %x", dec, input)
	}
}

func TestGCMRoundTripWithModifications(t *testing.T) {
	key := make([]byte, 32)
	input := []byte("hello this is Stripe")

	enc, err := encrypt(key, input, []byte("yay"))
	if err != nil {
		t.Fatal(err)
	}

	enc[5] ^= 1 // flip a bit

	dec, err := decrypt(key, enc, []byte("yay"))
	if err == nil {
		t.Fatalf("Was %x, but expected an error", dec)
	}
}

func TestGCMRoundTripWithBadData(t *testing.T) {
	key := make([]byte, 32)
	input := []byte("hello this is Stripe")

	enc, err := encrypt(key, input, []byte("yay"))
	if err != nil {
		t.Fatal(err)
	}

	dec, err := decrypt(key, enc, []byte("boo"))
	if err == nil {
		t.Fatalf("Was %x, but expected an error", dec)
	}
}
