package main

import (
	"encoding/base64"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/fatih/color"
	IBE "github.com/vanadium/go.lib/ibe"
)

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

func BenchmarkKeywordFEEncryption(b *testing.B) {

	words := []string{"feugiat"}
	color.Yellow("Number of words: %d", len(words))

	master, err := IBE.SetupBB2()
	if err != nil {
		b.Error(err)
	}

	publicParams = master.Params()

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		GenCiphTokens(master, words)
	}
}

func TestKeywordFESizeBlowup(t *testing.T) {
	color.Yellow("Number of words: %d", len(sampleWords))

	sum := 0
	for w := range sampleWords {
		sum += len([]byte(sampleWords[w]))
	}

	color.Yellow("Average word length plaintext (bytes): %f", float64(sum)/float64(len(sampleWords)))

	master, err := IBE.SetupBB2()
	if err != nil {
		t.Error(err)
	}

	tokens := GenCiphTokens(master, sampleWords)
	encSum := 0
	for i := range tokens {
		tok, _ := base64.URLEncoding.DecodeString(tokens[i])
		encSum += len(tok)
	}

	color.Yellow("[Encrypted] Average word length (bytes): %f", float64(encSum)/float64(len(sampleWords)))

	color.Cyan("Blowup: %f", float64(encSum)/float64(sum))
}

func TestShowKeywordFE(t *testing.T) {
	runtime.GOMAXPROCS(runtime.NumCPU())

	color.Yellow("Sample Text")
	fmt.Println(sampleText)
	color.Yellow("Sample Keywords")
	fmt.Println(sampleKeyWords)
	color.Yellow(".\n.\n.\nBegin Searching:")

	master, err := IBE.SetupBB2()
	if err != nil {
		panic(err)
	}

	publicParams = master.Params()

	var encrypedTokens = GenCiphTokens(master, sampleWords)
	var keywordSecretKeys = GenKeywordSKs(master, sampleKeyWords)

	ExtractEncryptedKeywords(encrypedTokens, keywordSecretKeys)
}
