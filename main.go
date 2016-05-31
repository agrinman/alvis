package main

import (
	"encoding/base64"
	"encoding/json"
	"path"
	"runtime"
	"strings"

	"io/ioutil"
	"os"

	"github.com/fatih/color"
	"github.com/urfave/cli"
	IBE "github.com/vanadium/go.lib/ibe"

	_ "net/http/pprof"
)

//MARK: Key types and parsing

type MasterKey struct {
	KeywordKey   KeyParams
	FrequencyKey FreqFEMasterKey
}

type KeyParams struct {
	Key    string `json:"key"`
	Params string `json:"params"`
}

func parseMasterKey(filepath string) (master IBE.Master, freq FreqFEMasterKey, err error) {
	mskBytes, err := ioutil.ReadFile(filepath)
	if err != nil {
		return
	}

	// unmarshall master secret
	var msk MasterKey
	err = json.Unmarshal(mskBytes, &msk)
	if err != nil {
		return
	}

	// ibe master
	mskKey, err := base64.StdEncoding.DecodeString(msk.KeywordKey.Key)
	if err != nil {
		return
	}
	mskParams, err := base64.StdEncoding.DecodeString(msk.KeywordKey.Params)
	if err != nil {
		return
	}

	params, err := IBE.UnmarshalParams(mskParams)
	if err != nil {
		return
	}

	master, err = IBE.UnmarshalMasterKey(params, mskKey)
	if err != nil {
		return
	}

	return master, msk.FrequencyKey, err
}

func parsePrivateKey(filepath string) (privateKey IBE.PrivateKey, err error) {
	kpBytes, err := ioutil.ReadFile(filepath)
	if err != nil {
		return
	}

	// unmarshall master secret
	var kp KeyParams
	err = json.Unmarshal(kpBytes, &kp)
	if err != nil {
		return
	}

	// ibe master
	kpKey, err := base64.StdEncoding.DecodeString(kp.Key)
	if err != nil {
		return
	}
	kpParams, err := base64.StdEncoding.DecodeString(kp.Params)
	if err != nil {
		return
	}

	params, err := IBE.UnmarshalParams(kpParams)
	if err != nil {
		return
	}

	privateKey, err = IBE.UnmarshalPrivateKey(params, kpKey)
	if err != nil {
		return
	}

	return
}

func genMaster(c *cli.Context) (err error) {
	if c.NumFlags() < 1 {
		color.Red("Missing '-out' flag for filepath of master key")
		return
	}

	outPath := c.String("out")

	// setup frequency key
	freqMaster, err := GenFrequencyFE()
	if err != nil {
		color.Red(err.Error())
		return
	}

	// setup ibe key
	ibeMaster, err := IBE.SetupBB2()
	if err != nil {
		color.Red(err.Error())
		return
	}

	// marshall ibe master key
	masterBytes, err := IBE.MarshalMasterKey(ibeMaster)
	if err != nil {
		color.Red(err.Error())
		return
	}
	masterB64 := base64.StdEncoding.EncodeToString(masterBytes)

	paramsBytes, err := IBE.MarshalParams(ibeMaster.Params())
	if err != nil {
		color.Red(err.Error())
		return
	}
	paramsB64 := base64.StdEncoding.EncodeToString(paramsBytes)

	msk := MasterKey{KeyParams{masterB64, paramsB64}, freqMaster}

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

	master, _, err := parseMasterKey(mskPath)
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

func genFrequencyKey(c *cli.Context) (err error) {
	if c.NumFlags() < 3 {
		color.Red("Missing 'msk' for path to master secret key OR '-word' for the keyword OR '-out' flag for filepath of search keyword secret key")
		return
	}

	// read master secret file
	mskPath := c.String("msk")

	_, freq, err := parseMasterKey(mskPath)
	if err != nil {
		color.Red(err.Error())
		return
	}

	outBytes := freq.OuterKey

	// get outPath
	outPath := c.String("out")

	// write file
	err = ioutil.WriteFile(outPath, outBytes, 0660)

	return
}

func encrypt(c *cli.Context) (err error) {
	if c.NumFlags() < 3 {
		color.Red("Missing 'msk' for path to master secret key OR '-patient-dir' for directory of patient files OR '-out-dir' for the directory of the encrypted patient files")
		return
	}

	// read master secret file
	mskPath := c.String("msk")
	master, freq, err := parseMasterKey(mskPath)
	if err != nil {
		color.Red(err.Error())
		return
	}

	// get and mkdir out path
	outPath := c.String("out-dir")
	os.MkdirAll(outPath, 0777)

	// read patient files
	patientDirPath := c.String("patient-dir")

	file, _ := os.Open(patientDirPath)
	fi, err := file.Stat()
	if err != nil {
		color.Red("Cannot get file info: %s", err)
		return
	}

	switch mode := fi.Mode(); {
	case mode.IsDir():
		files, _ := ioutil.ReadDir(patientDirPath)

		for _, f := range files {
			in := path.Join(patientDirPath, f.Name())
			out := path.Join(outPath, f.Name()+".enc")

			err = EncryptAndSavePatientFile(in, out, master, freq)
			if err != nil {
				color.Red("Cannot EncryptAndSavePatientFile: %s", err)
				return
			}
		}

	case mode.IsRegular():
		color.Red("'-patient-dir' was given a file. expected a directory.")
		break
	}

	return
}

func decrypt(c *cli.Context) (err error) {
	if c.NumFlags() < 3 {
		color.Red("Missing 'key-dir' for directory path to functional keys key OR '-freq-key' for path to the frequency decryption key file OR '-patient-dir' for directory of patient files OR '-out-dir' for the where to write the partially-decrypted patient files")
		return
	}

	// read freq key
	freqKeyPath := c.String("freq-key")
	freqOuterKey, err := ioutil.ReadFile(freqKeyPath)
	if err != nil {
		color.Red("Cannot read freq key: %s", err)
		return
	}

	// read all functional keys
	keyDirPath := c.String("key-dir")

	file, _ := os.Open(keyDirPath)
	fi, err := file.Stat()
	if err != nil {
		color.Red("Cannot read %s. Error: %s", keyDirPath, err)
		return
	}

	var keywordKeys []IBE.PrivateKey

	switch mode := fi.Mode(); {
	case mode.IsDir():
		files, _ := ioutil.ReadDir(keyDirPath)
		for _, f := range files {
			fpath := path.Join(keyDirPath, f.Name())

			// try to parse as ibe.private key
			privateKey, parseErr := parsePrivateKey(fpath)
			if parseErr == nil {
				keywordKeys = append(keywordKeys, privateKey)
			} else {
				color.Red("Could not parse keyword key %s. Got err: %s", fpath, err)
			}
		}
	case mode.IsRegular():
		color.Red("Error '-key-dir' was given a file. expected a directory.")
		return
	}

	// get and mkdir out path
	outPath := c.String("out-dir")
	os.MkdirAll(outPath, 0660)

	// read patient files
	patientDirPath := c.String("patient-dir")

	file, _ = os.Open(patientDirPath)
	fi, err = file.Stat()
	if err != nil {
		color.Red("Cannot read %s. Error: %s", patientDirPath, err)
		return
	}

	switch mode := fi.Mode(); {
	case mode.IsDir():
		files, _ := ioutil.ReadDir(patientDirPath)
		for _, f := range files {

			in := path.Join(patientDirPath, f.Name())
			out := path.Join(outPath, strings.Replace(f.Name(), ".enc", "", 1))

			err = DecryptAndSavePatientFile(in, out, keywordKeys, freqOuterKey)
			if err != nil {
				color.Red("Cannot EncryptAndSavePatientFile: %s", err)
				return
			}
		}
	case mode.IsRegular():
		color.Red("'-patient-dir' was given a file. expected a directory.")
		break
	}

	return
}

//MARK: CLI
func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	// go func() {
	// 	log.Println(http.ListenAndServe("localhost:6060", nil))
	// }()

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
			Usage:   "Generate a secret, functional decryption key for: keyword or frequency",
			Subcommands: []cli.Command{
				{
					Name:   "keyword",
					Usage:  "search keyword functional key",
					Action: genKeywordKey,
					Flags: []cli.Flag{
						cli.StringFlag{Name: "word"},
						cli.StringFlag{Name: "msk"},
						cli.StringFlag{Name: "out"},
					},
				},
				{
					Name:   "frequency",
					Usage:  "functional key for computing frequency count",
					Action: genFrequencyKey,
				},
			},
		},
		{
			Name:    "encrypt",
			Aliases: nil,
			Usage:   "Encrypt patient files",
			Action:  encrypt,
			Flags: []cli.Flag{
				cli.StringFlag{Name: "msk"},
				cli.StringFlag{Name: "patient-dir"},
				cli.StringFlag{Name: "out-dir"},
			},
		},
		{
			Name:    "decrypt",
			Aliases: nil,
			Usage:   "Decrypt patient files",
			Action:  decrypt,
			Flags: []cli.Flag{
				cli.StringFlag{Name: "key-dir"},
				cli.StringFlag{Name: "freq-key"},
				cli.StringFlag{Name: "patient-dir"},
				cli.StringFlag{Name: "out-dir"},
			},
		},
	}

	app.Run(os.Args)
}
