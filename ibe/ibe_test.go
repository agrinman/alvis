package ibe

import (
	"crypto/sha256"
	"fmt"
	"os"
	"runtime"
	"testing"
)

func TestMain(m *testing.M) {
	runtime.GOMAXPROCS(runtime.NumCPU() - 1)

	os.Exit(m.Run())
}

// TestGenAndEval tests functionality
func TestOnlyIBE(t *testing.T) {
	fmt.Println("Run 10 times...")
	for i := 0; i < 10; i++ {
		msk, pp := DefaultSetup()
		sk := msk.Extract("feugiat")

		m := pp.Pairing.NewGT().SetFromStringHash("true", sha256.New())
		c := pp.Encrypt("feugiat", m)

		ret := pp.Decrypt(sk, c).Bytes()

		exp := m.Bytes()

		if !checkResultFull(ret, exp) {
			t.Errorf("Got back: %d. \nExpected %d", ret, exp)
			return
		}
	}
}

func TestIBEWithMarshal(t *testing.T) {

	msk, pp := DefaultSetup()
	sk := msk.Extract("feugiat")
	c := pp.EncryptKeyword("feugiat")

	// marhsall all
	res_msk, err := MarshalMasterKey(msk)
	if err != nil {
		t.Error(err)
		return
	}
	res_sk, err := MarshallPrivateKey(pp, sk)
	if err != nil {
		t.Error(err)
		return
	}
	res_ctxt, err := MarshallCipherText(pp, c)
	if err != nil {
		t.Error(err)
		return
	}

	// unmarhsal all

	msk2, err := UnmarshalMasterKey(res_msk)
	if err != nil {
		t.Error(err)
		return
	}

	sk2, err := UnmarshalPrivateKey(msk2.Params, res_sk)
	if err != nil {
		t.Error(err)
		return
	}

	c2, err := UnmarshalCipherText(msk2.Params, res_ctxt)
	if err != nil {
		t.Error(err)
		return
	}

	// check it all works out
	ret := msk2.Params.DecryptAndCheck(sk2, c2)

	if !ret {
		t.Errorf("Got %d\nExpected %d", msk2.Params.Decrypt(sk2, c2).Bytes(), pp.Pairing.NewGT().SetFromStringHash("true", sha256.New()).Bytes())
		return
	}

}

// func TestIBEParallel(t *testing.T) {
// 	_, pp := DefaultSetup()
//
// 	var wg sync.WaitGroup
// 	wg.Add(1000)
//
// 	for i := 0; i < 1000; i++ {
// 		go func(w *sync.WaitGroup) {
// 			_ = pp.Encrypt("feugiatfeugiatfeugiatfeugiat", []byte{0x01})
// 			w.Done()
// 		}(&wg)
// 	}
//
// 	wg.Wait()
// }

func BenchmarkIBEEncrypt(b *testing.B) {
	_, pp := DefaultSetup()
	m := pp.Pairing.NewGT().SetFromStringHash("true", sha256.New())

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_ = pp.Encrypt("feugiatfeugiatfeugiatfeugiat", m)
	}
}

//MARK: Helpers

func checkResult(got []byte, exp []byte) bool {
	if got[0] != exp[0] {
		return false
	}

	return true
}

func checkResultFull(got []byte, exp []byte) bool {
	if len(got) != len(exp) {
		return false
	}

	success := true
	for i := range got {

		if got[i] != exp[i] {
			success = false
			break
		}
	}

	return success
}
