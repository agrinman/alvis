package pfs

import "testing"
import "bytes"

func TestPFS(t *testing.T) {
	master, err := Setup()
	if err != nil {
		t.Error(err)
	}
	message := []byte("hello world")
	ctxt, err := Disguise(master, message)
	if err != nil {
		t.Error(err)
	}

	_, err = RecognizeCiphertext(master.OuterKey, ctxt)
	if err != nil {
		t.Error(err)
	}

	out, err := UncoverCiphertext(master, ctxt)
	if err != nil {
		t.Error(err)
	}

	if bytes.Equal(message, out) == false {
		t.Errorf("Output does not match orginal message.\nGot: %s\nExpected: %s", out, message)
	}

}
