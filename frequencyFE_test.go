package main

import "testing"
import "bytes"

func TestFrequencyFE(t *testing.T) {
	inner, outer, err := GenFrequencyFE()
	if err != nil {
		t.Error(err)
	}
	message := []byte("hello world")
	ctxt, err := EncryptInnerOuter(inner, outer, message)
	if err != nil {
		t.Error(err)
	}

	innerCtxt, err := DecryptOuter(outer, ctxt)
	if err != nil {
		t.Error(err)
	}

	out, err := DecryptInner(inner, innerCtxt)
	if err != nil {
		t.Error(err)
	}

	if bytes.Equal(message, out) == false {
		t.Errorf("Output does not match orginal message.\nGot: %s\nExpected: %s", out, message)
	}

}
