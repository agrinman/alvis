package privKS

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}

func BenchmarkKeywordDecrypt(b *testing.B) {
	master, _ := GenMasterKey()
	c, _ := master.EncryptKeyword("ullamcorper")
	sk := master.Extract("ullamcorper")

	b.ResetTimer()
	v := true
	for n := 0; n < b.N; n++ {
		v = v && sk.DecryptAndCheck(c)
	}

	if !v {
		b.Errorf("failed decrypt")
		return
	}

}

func TestNewLineCarriageReturn(t *testing.T) {

	master, _ := GenMasterKey()
	c, _ := master.EncryptKeyword("\n")
	sk := master.Extract("\n")

	if !sk.DecryptAndCheck(c) {
		t.Error("Error: mismatch newline")
		return
	}

	c, _ = master.EncryptKeyword("\r")
	sk = master.Extract("\r")

	if !sk.DecryptAndCheck(c) {
		t.Error("Error: mismatch carriage return")
		return
	}

}
