package pfs

import "testing"
import "bytes"

var longWord = "supercalifragilisticexpialidocious"

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

func BenchmarkSetup(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			Setup()
		}
	})
}

func BenchmarkDisguise(b *testing.B) {
	master, _ := Setup()

	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			Disguise(master, []byte(longWord))
		}
	})
}

func BenchmarkRecognize(b *testing.B) {
	master, _ := Setup()
	c, _ := Disguise(master, []byte(longWord))
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			Recognize(master.OuterKey, c.Hidden)
		}
	})

}
