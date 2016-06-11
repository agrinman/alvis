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
