package base36

import (
	"crypto/rand"
	"fmt"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}

func TestEncodeDecode(t *testing.T) {
	s := "hello, my friend how are you?"
	fmt.Println("Original: ", s)

	es, err := EncodeString(s)
	if err != nil {
		t.Error("Error:", err)
		return
	}
	fmt.Println("Base 36: ", es)

	ds, err := DecodeString(es)
	if err != nil {
		t.Errorf("Could not decode: %s\n", err)
		return
	}

	if string(ds) != s {
		t.Errorf("Strings don't match. Got %s. Expected %s.", string(ds), s)
	}
}

func TestRandEncodeDecode(t *testing.T) {

	for i := 0; i < 1000; i++ {
		s := make([]byte, 2048/8)
		_, err := rand.Read(s)
		if err != nil {
			t.Error("rand error:", err)
			return
		}

		//fmt.Println("Original: ", s)

		es, err := Encode(s)
		if err != nil {
			t.Error("Error:", err)
			return
		}
		//fmt.Println("Base 36: ", es)

		ds, err := DecodeString(es)
		if err != nil {
			t.Errorf("Could not decode: %s\n", err)
			return
		}

		if len(ds) != len(s) {
			t.Errorf("Bytes don't match. Got %s. Expected %s.", string(ds), s)
			return
		}

		for i := range ds {
			if ds[i] != s[i] {
				t.Errorf("Bytes don't match @ byte %d. Got %d. Expected %d.", i, ds[i], s[i])
			}
		}
	}
}
