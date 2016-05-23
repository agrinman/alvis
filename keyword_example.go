package main

import (
	"fmt"
	"runtime"

	"github.com/fatih/color"
	IBE "github.com/vanadium/go.lib/ibe"
)

const (
	sampleText = `Pellentesque sed viverra nisi, ut sollicitudin felis. Curabitur lorem neque, pulvinar vel porta et, euismod dignissim turpis. Nullam consequat sapien leo, ac rhoncus tortor imperdiet a. Praesent condimentum nunc ante, at cursus diam maximus vitae. In eleifend aliquam velit, eget fermentum nunc. Integer sit lorem lacus porta, rutrum lacus vel, felis felis. In ut metus lacinia erat dapibus accumsan. Nulla facilisi. Ut ut lectus feugiat lorem felis vestibulum. Ut lorem, diam in posuere vehicula, nulla turpis venenatis tortor, nec ullamcorper dolor neque et ligula. Suspendisse eu libero vel erat congue tempor non molestie arcu. Donec auctor, sem vitae malesuada lobortis, lorem eros accumsan nibh, id tempus risus lorem quis nullam. Sed euismod rhoncus elit, non eleifend tortor fringilla felis. Aliquam erat volutpat. Morbi interdum elit nec efficitur malesuada.`
)

var sampleKeyWords = []string{"lorem", "felis", "eros", "porta"}

func oldMain() {
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

	var encrypedTokens = GenCiphTokens(master, sampleText)
	var keywordSecretKeys = GenKeywordSKs(master, sampleKeyWords)

	ExtractEncryptedKeywords(encrypedTokens, keywordSecretKeys)
}
