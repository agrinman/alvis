package ibe

import (
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
func TestIBE(t *testing.T) {
	msk, pp := DefaultSetup()
	sk := msk.Extract("feugiat")

	m := []byte{0xAA}
	c := pp.Encrypt("feugiat", m)

	ret := pp.Decrypt(sk, c)
	fmt.Println()

	exp := pp.ValBytes(m)
	if len(exp) != len(ret) {
		t.Errorf("Got back: %d. \nExpected %d", ret, exp)
		return
	}

	success := true
	last := 0
	for i := range ret {
		last = i

		if ret[i] != exp[i] {
			success = false
			break
		}
	}

	if !success {
		t.Errorf("Error at byte %d.\nGot back: %d. \nExpected %d", last, ret, exp)
		return
	}
}

func TestIBEWithMarshal(t *testing.T) {

	msk, pp := DefaultSetup()
	sk := msk.Extract("feugiat")
	m := []byte{0xAA}
	c := pp.Encrypt("feugiat", m)

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

	fmt.Println(string(res_msk))
	fmt.Println(string(res_sk))
	fmt.Println(string(res_ctxt))

	// unmarhsal all

	_, err = UnmarshalMasterKey(res_msk)
	if err != nil {
		t.Error(err)
		return
	}

	_, _, err = UnmarshalPrivateKey(res_sk)
	if err != nil {
		t.Error(err)
		return
	}

	_, err = UnmarshalCipherText(pp, res_ctxt)
	if err != nil {
		t.Error(err)
		return
	}

	// check it all works out
	ret := msk.Params.Decrypt(sk, c)

	exp := pp.ValBytes(m)
	if len(exp) != len(ret) {
		t.Errorf("Got back: %d. \nExpected %d", ret, exp)
		return
	}

	success := true
	last := 0
	for i := range ret {
		last = i

		if ret[i] != exp[i] {
			success = false
			break
		}
	}

	if !success {
		t.Errorf("Error at byte %d.\nGot back: %d. \nExpected %d", last, ret, exp)
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

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_ = pp.Encrypt("feugiatfeugiatfeugiatfeugiat", []byte{0x01})
	}
}
