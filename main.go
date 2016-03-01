package main

import (
	"encoding/base64"
	"fmt"
	"github.com/fatih/color"
	IBE "github.com/vanadium/go.lib/ibe"
	"runtime"
	"strings"
)

const (
	sampleText = `Pellentesque sed viverra nisi, ut sollicitudin felis. Curabitur lorem neque, pulvinar vel porta et, euismod dignissim turpis. Nullam consequat sapien leo, ac rhoncus tortor imperdiet a. Praesent condimentum nunc ante, at cursus diam maximus vitae. In eleifend aliquam velit, eget fermentum nunc. Integer sit lorem lacus porta, rutrum lacus vel, felis felis. In ut metus lacinia erat dapibus accumsan. Nulla facilisi. Ut ut lectus feugiat lorem felis vestibulum. Ut lorem, diam in posuere vehicula, nulla turpis venenatis tortor, nec ullamcorper dolor neque et ligula. Suspendisse eu libero vel erat congue tempor non molestie arcu. Donec auctor, sem vitae malesuada lobortis, lorem eros accumsan nibh, id tempus risus lorem quis nullam. Sed euismod rhoncus elit, non eleifend tortor fringilla felis. Aliquam erat volutpat. Morbi interdum elit nec efficitur malesuada.`
)

var sampleKeyWords = []string{"lorem", "felis", "eros", "porta"}

// Keyword struct holds the plain-text and encrypted
type Keyword struct {
	Word       string
	PrivateKey IBE.PrivateKey
}

var publicParams IBE.Params

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	master, err := IBE.SetupBB2()
	if err != nil {
		panic(err)
	}

	publicParams = master.Params()

	var encrypedTokens = GenCiphTokens(master, sampleText)
	var keywordSecretKeys = GenKeywordSKs(master, sampleKeyWords)

	ExtractEncryptedKeywords(encrypedTokens, keywordSecretKeys)
}

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
func GenCiphTokens(m IBE.Master, data string) []string {
	filteredText := strings.Replace(data, ".", "", -1)
	filteredText = strings.Replace(filteredText, ",", "", -1)
	tokens := strings.Split(filteredText, " ")
	fmt.Println("Plaintext Key Word Count: ", computeWordCount(tokens, sampleKeyWords))

	ciphTokens := make([]string, len(tokens))
	for i, t := range tokens {
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
				fmt.Printf("Decrypted Keyword (%s) from Ciphertext (%s...%s)\n", color.GreenString(sk.Word), color.YellowString(v[0:5]), color.YellowString(v[len(v)-5:]))
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
		totals += fmt.Sprintf("%s: %d\n", k.Word, foundCount[i])
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
