package main

import (
	"encoding/base64"
	"encoding/json"

	"io/ioutil"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/urfave/cli"
	IBE "github.com/vanadium/go.lib/ibe"
)

//MARK: Encrypt/decrypt free text
func encryptor(data interface{}) map[string][]string {
	// words := SplitFreeText(data.(string))
	//
	// //keyword
	//
	// make(map[string][]string)

	return make(map[string][]string)
}

func decryptor(data interface{}) string {
	_ = data.(map[string][]string)
	return ""
}

//MARK: Free text helpers
func SplitFreeText(text string) []string {
	filteredText := strings.Replace(text, ".", "", -1)
	filteredText = strings.Replace(filteredText, ",", "", -1)
	return strings.Split(filteredText, " ")
}

//MARK: ClI Commands

type KeyParams struct {
	Key    string `json:"key"`
	Params string `json:"params"`
}

func genMaster(c *cli.Context) (err error) {
	if c.NumFlags() < 1 {
		color.Red("Missing '-out' flag for filepath of master key")
		return
	}

	outPath := c.String("out")

	master, err := IBE.SetupBB2()
	if err != nil {
		color.Red(err.Error())
		return
	}

	// marshall master key
	masterBytes, err := IBE.MarshalMasterKey(master)
	if err != nil {
		color.Red(err.Error())
		return
	}
	masterB64 := base64.StdEncoding.EncodeToString(masterBytes)

	paramsBytes, err := IBE.MarshalParams(master.Params())
	if err != nil {
		color.Red(err.Error())
		return
	}
	paramsB64 := base64.StdEncoding.EncodeToString(paramsBytes)

	msk := KeyParams{masterB64, paramsB64}

	outBytes, err := json.Marshal(msk)
	if err != nil {
		color.Red(err.Error())
		return
	}

	// write file
	err = ioutil.WriteFile(outPath, outBytes, 0660)

	return
}

func genKeywordKey(c *cli.Context) (err error) {
	if c.NumFlags() < 3 {
		color.Red("Missing 'msk' for path to master secret key OR '-word' for the keyword OR '-out' flag for filepath of search keyword secret key")
		return
	}

	// read master secret file
	mskPath := c.String("msk")
	mskBytes, err := ioutil.ReadFile(mskPath)
	if err != nil {
		color.Red(err.Error())
		return
	}

	// unmarshall master secret
	var msk KeyParams
	err = json.Unmarshal(mskBytes, &msk)
	if err != nil {
		color.Red(err.Error())
		return
	}

	mskKey, err := base64.StdEncoding.DecodeString(msk.Key)
	if err != nil {
		color.Red(err.Error())
		return
	}
	mskParams, err := base64.StdEncoding.DecodeString(msk.Params)
	if err != nil {
		color.Red(err.Error())
		return
	}

	params, err := IBE.UnmarshalParams(mskParams)
	if err != nil {
		color.Red(err.Error())
		return
	}

	master, err := IBE.UnmarshalMasterKey(params, mskKey)
	if err != nil {
		color.Red(err.Error())
		return
	}

	// gen secret key
	word := c.String("word")
	secretKey, err := master.Extract(word)
	if err != nil {
		color.Red(err.Error())
		return
	}

	// marshall secretKey and params
	skBytes, err := IBE.MarshalPrivateKey(secretKey)
	if err != nil {
		color.Red(err.Error())
		return
	}

	skB64 := base64.StdEncoding.EncodeToString(skBytes)

	paramBytes, err := IBE.MarshalParams(secretKey.Params())
	if err != nil {
		color.Red(err.Error())
		return
	}

	paramB64 := base64.StdEncoding.EncodeToString(paramBytes)

	sk := KeyParams{skB64, paramB64}

	outBytes, err := json.Marshal(sk)
	if err != nil {
		color.Red(err.Error())
		return
	}

	// get outPath
	outPath := c.String("out")

	// write file
	err = ioutil.WriteFile(outPath, outBytes, 0660)

	return
}

func encrypt(c *cli.Context) (err error) {
	return
}

func decrypt(c *cli.Context) (err error) {
	return
}

//MARK: CLI
func main() {
	app := cli.NewApp()

	app.Name = color.GreenString("Alvis")
	app.Usage = color.GreenString("A command line utility to encrypt and partially-decrypt patient files for searching on encrypted data")
	app.EnableBashCompletion = true
	app.Version = "0.1"

	app.Commands = []cli.Command{
		{
			Name:    "gen-msk",
			Aliases: nil,
			Usage:   "Generate master private key",
			Action:  genMaster,
			Flags: []cli.Flag{
				cli.StringFlag{Name: "out"},
			},
		},
		{
			Name:    "gen-sk",
			Aliases: nil,
			Usage:   "Generate a secret, functional decryption key, for a search keyword",
			Action:  genKeywordKey,
			Flags: []cli.Flag{
				cli.StringFlag{Name: "msk"},
				cli.StringFlag{Name: "word"},
				cli.StringFlag{Name: "out"},
			},
		},
		{
			Name:    "encrypt",
			Aliases: nil,
			Usage:   "Encrypt patient files...specify directory of patient files, and output",
			Action:  encrypt,
		},
		{
			Name:    "decrypt",
			Aliases: nil,
			Usage:   "Decrypt patient files...specify directory of patient files, and output",
			Action:  decrypt,
		},
	}

	app.Run(os.Args)
}
