package ibe

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/fatih/color"
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

	fmt.Println("Run 10 times...")
	for i := 0; i < 10; i++ {

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
		res_ctxt, err := MarshalCipherTextBase64(c)
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

		c2, err := UnmarshalCipherTextBase64(msk2.Params, res_ctxt)
		if err != nil {
			t.Error(err)
			return
		}

		// check it all works out
		ret := msk2.Params.DecryptAndCheck(sk2, c2)

		if !ret {
			t.Errorf("[it %d] Got %d\nExpected %d", i, msk2.Params.Decrypt(sk2, c2).Bytes(), pp.TrueEl.Bytes())
			return
		}
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

func BenchmarkIBEDecrypt(b *testing.B) {
	master, pp := DefaultSetup()
	c := pp.EncryptKeyword("ullamcorper")
	sk := master.Extract("ullamcorper")

	b.ResetTimer()
	v := true
	for n := 0; n < b.N; n++ {
		v = v && pp.DecryptAndCheck(sk, c)
	}

	if !v {
		b.Errorf("failed decrypt")
		return
	}

}

const (
	sampleText = `Pellentesque sed viverra nisi, ut sollicitudin felis. Curabitur lorem neque, pulvinar vel porta et, euismod dignissim turpis. Nullam consequat sapien leo, ac rhoncus tortor imperdiet a. Praesent condimentum nunc ante, at cursus diam maximus vitae. In eleifend aliquam velit, eget fermentum nunc. Integer sit lorem lacus porta, rutrum lacus vel, felis felis. In ut metus lacinia erat dapibus accumsan. Nulla facilisi. Ut ut lectus feugiat lorem felis vestibulum. Ut lorem, diam in posuere vehicula, nulla turpis venenatis tortor, nec ullamcorper dolor neque et ligula. Suspendisse eu libero vel erat congue tempor non molestie arcu. Donec auctor, sem vitae malesuada lobortis, lorem eros accumsan nibh, id tempus risus lorem quis nullam. Sed euismod rhoncus elit, non eleifend tortor fringilla felis. Aliquam erat volutpat. Morbi interdum elit nec efficitur malesuada.`
)

var sampleKeyWords = []string{"lorem", "felis", "eros", "porta"}

func getSampleTextWords() []string {
	filteredText := strings.Replace(sampleText, ".", "", -1)
	filteredText = strings.Replace(filteredText, ",", "", -1)
	return strings.Split(filteredText, " ")
}

var sampleWords = getSampleTextWords()

func TestKeywordFESizeBlowup(t *testing.T) {
	color.Yellow("Number of words: %d", len(sampleWords))

	sum := 0
	for w := range sampleWords {
		sum += len([]byte(sampleWords[w]))
	}

	color.Yellow("Average word length plaintext (bytes): %f", float64(sum)/float64(len(sampleWords)))

	_, pp := DefaultSetup()
	encSum := 0
	for _, t := range sampleWords {
		ctxt, _ := MarshalCipherTextBase64(pp.EncryptKeyword(t))
		ctxtBytes, _ := base64.URLEncoding.DecodeString(ctxt)

		encSum += len(ctxtBytes)
	}

	color.Yellow("[Encrypted] Average word length (bytes): %f", float64(encSum)/float64(len(sampleWords)))

	color.Cyan("Blowup: %f", float64(encSum)/float64(sum))
}

func TestShowIBEKeyword(t *testing.T) {
	runtime.GOMAXPROCS(runtime.NumCPU())

	color.Yellow("Sample Text")
	fmt.Println(sampleText)
	color.Yellow("Sample Keywords")
	fmt.Println(sampleKeyWords)
	color.Yellow(".\n.\n.\nBegin Searching:")

	master, pp := DefaultSetup()

	encryptedTokens := make([]CipherText, len(sampleWords))
	for i, t := range sampleWords {
		encryptedTokens[i] = pp.EncryptKeyword(t)
	}

	keywordSecretKeys := make([]PrivateKey, len(sampleKeyWords))
	for i, t := range sampleKeyWords {
		keywordSecretKeys[i] = master.Extract(t)
	}

	// extract

	var foundCount = make([]int, len(keywordSecretKeys))
	var done = make(chan bool)

	extractor := func(i int, params PublicParams, sk PrivateKey) {
		for _, v := range encryptedTokens {
			if pp.DecryptAndCheck(sk, v) {
				ctxt, _ := MarshallCipherText(pp, v)
				vb64 := base64.URLEncoding.EncodeToString(SHA2(ctxt.Unique()))

				fmt.Printf("Decrypted Keyword (%s) from Ciphertext (%s)\n", color.GreenString(sampleKeyWords[i]), color.YellowString(vb64))
				foundCount[i]++
			}
		}

		done <- true
	}

	for i, sk := range keywordSecretKeys {
		go extractor(i, pp, sk)
	}

	for i := 0; i < len(keywordSecretKeys); i++ {
		<-done
	}

	color.Cyan("Done!")

	totals := ""
	for i, k := range sampleKeyWords {
		totals += fmt.Sprintf("%s: \t%d\n", k, foundCount[i])
	}

	color.Green("Extracted Keywords:\n%s", totals)

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
