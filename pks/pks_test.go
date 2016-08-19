package pks

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}

func BenchmarkKeywordDecrypt(b *testing.B) {
	master, _ := Setup()
	c, _ := master.Hide("ullamcorper")
	sk := master.Extract("ullamcorper")

	b.ResetTimer()
	v := true
	for n := 0; n < b.N; n++ {
		v = v && sk.Check(c)
	}

	if !v {
		b.Errorf("failed decrypt")
		return
	}

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
