package main

import (
	"encoding/base64"
	"fmt"

	"github.com/fatih/color"
	IBE "github.com/vanadium/go.lib/ibe"
)

// Keyword struct holds the plain-text and encrypted
type Keyword struct {
	Word       string
	PrivateKey IBE.PrivateKey
}

var publicParams IBE.Params

// GenKeywordSKs creates sk's for each keyword
func GenKeywordSKs(m IBE.Master, keywords []string) []Keyword {
	secretKeys := make([]Keyword, len(keywords))

	for i, k := range keywords {
		sk, err := m.Extract(k)
		if err != nil {
			panic(err)
		}

		secretKeys[i] = Keyword{Word: k, PrivateKey: sk}
	}

	return secretKeys
}

// GenCiphTokens creates sk's for each keyword
func GenCiphTokens(m IBE.Master, data []string) []string {

	ciphTokens := make([]string, len(data))
	for i, t := range data {
		ciph := make([]byte, 1+m.Params().CiphertextOverhead())
		m.Params().Encrypt(t, []byte{0x01}, ciph)

		ciphTokens[i] = base64.URLEncoding.EncodeToString(ciph)
	}

	return ciphTokens
}

// ExtractEncryptedKeywords searches through encryptedTokens, and tries to decrypts
// if it can decrypt, then
func ExtractEncryptedKeywords(encryptedTokens []string, keywords []Keyword) {
	var foundCount = make([]int, len(keywords))
	var done = make(chan bool)

	extractor := func(i int, sk Keyword) {
		for _, v := range encryptedTokens {
			cipherBytes, err := base64.URLEncoding.DecodeString(v)
			if err != nil {
				panic(err)
			}

			message := make([]byte, 1)
			decryptErr := sk.PrivateKey.Decrypt(cipherBytes, message)
			if decryptErr != nil {
				// log.Println("Found Decryption Err:", decryptErr)
				continue
			}

			if message[0] == 0x01 {
				fmt.Printf("Decrypted Keyword (%s) from Ciphertext (%s...%s)\n", color.GreenString(sk.Word), color.YellowString(v[0:8]), color.YellowString(v[len(v)-8:]))
				foundCount[i]++
			}
		}

		done <- true
	}

	for i, sk := range keywords {
		go extractor(i, sk)
	}

	for i := 0; i < len(keywords); i++ {
		<-done
	}

	color.Cyan("Done!")

	totals := ""
	for i, k := range keywords {
		totals += fmt.Sprintf("%s: \t%d\n", k.Word, foundCount[i])
	}

	color.Green("Extracted Keywords:\n%s", totals)
}

//MARK: Helpers
func computeWordCount(tokens, keys []string) []int {
	countMap := make(map[string]int)
	for _, t := range tokens {
		if _, ok := countMap[t]; ok {
			countMap[t]++
		} else {
			countMap[t] = 1
		}
	}
	wcs := make([]int, len(keys))
	for i, k := range keys {
		if _, ok := countMap[k]; ok {
			wcs[i] = countMap[k]
		}
	}
	return wcs
}
