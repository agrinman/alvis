package pks

import (
	"os"
	"testing"
)

var longWord = "supercalifragilisticexpialidocious"

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}

func BenchmarkSetup(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			Setup()
		}
	})
}

func BenchmarkExtract(b *testing.B) {
	master, _ := Setup()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			master.Extract(longWord)
		}
	})
}

func BenchmarkHide(b *testing.B) {
	master, _ := Setup()

	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			master.Hide(longWord)
		}
	})
}

func BenchmarkCheck(b *testing.B) {
	master, _ := Setup()
	c, _ := master.Hide(longWord)
	sk := master.Extract(longWord)

	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {

		v := true
		for pb.Next() {
			v = v && sk.Check(c)
		}

		if !v {
			b.Errorf("failed decrypt")
			return
		}
	})

}

func TestNewLineCarriageReturn(t *testing.T) {

	master, _ := Setup()
	c, _ := master.Hide("\n")
	sk := master.Extract("\n")

	if !sk.Check(c) {
		t.Error("Error: mismatch newline")
		return
	}

	c, _ = master.Hide("\r")
	sk = master.Extract("\r")

	if !sk.Check(c) {
		t.Error("Error: mismatch carriage return")
		return
	}

}
