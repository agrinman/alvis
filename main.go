package main

import (
	"encoding/json"
	"log"
	"path"
	"runtime"

	"strings"

	"io/ioutil"
	"os"

	"github.com/agrinman/alvis/ibe"

	"github.com/fatih/color"
	"github.com/urfave/cli"

	"net/http"
	_ "net/http/pprof"
)

//MARK: Key types and parsing

type MasterKey struct {
	KeywordKey   ibe.MasterKeySerialized
	FrequencyKey FreqFEMasterKey
}

type KeyParams struct {
	Key    ibe.PrivateKeySerialized   `json:"key"`
	Params ibe.PublicParamsSerialized `json:"params"`
}

func parseMasterKey(filepath string) (master ibe.MasterKey, freq FreqFEMasterKey, err error) {
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
	master, err = ibe.UnmarshalMasterKey(msk.KeywordKey)
	if err != nil {
		return
	}

	return master, msk.FrequencyKey, err
}

func parseParams(filepath string) (params ibe.PublicParams, err error) {
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

	params, err = kp.Params.ToPublicParams()

	return
}

func parsePrivateKey(params ibe.PublicParams, filepath string) (privateKey ibe.PrivateKey, err error) {
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

	privateKey, err = ibe.UnmarshalPrivateKey(params, kp.Key)
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
	ibeMaster, _ := ibe.DefaultSetup()

	// marshall ibe master key
	masterSer, err := ibe.MarshalMasterKey(ibeMaster)
	if err != nil {
		return
	}

	msk := MasterKey{masterSer, freqMaster}

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
	secretKey := master.Extract(word)

	// marshall secretKey and params
	skSer, err := ibe.MarshallPrivateKey(master.Params, secretKey)
	if err != nil {
		color.Red(err.Error())
		return
	}

	paramSer := master.Params.ToSerialized()

	sk := KeyParams{skSer, paramSer}

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

	var keywordKeys []ibe.PrivateKey
	var params ibe.PublicParams
	var errParams error

	switch mode := fi.Mode(); {
	case mode.IsDir():
		files, _ := ioutil.ReadDir(keyDirPath)
		if len(files) == 0 {
			color.Yellow("No functional keyword keys found in key dir %s. Skipping keyword decryptions.", keyDirPath)
			break
		}

		params, errParams = parseParams(path.Join(keyDirPath, files[0].Name()))
		if errParams != nil {
			color.Red("Could not read system parameters. Invalid keword functional key: %s. Error: %s", path.Join(keyDirPath, files[0].Name()), errParams)
			return
		}
		//read all keys
		for _, f := range files {
			fpath := path.Join(keyDirPath, f.Name())

			// try to parse as ibe.private key
			privateKey, parseErr := parsePrivateKey(params, fpath)
			if parseErr == nil {
				keywordKeys = append(keywordKeys, privateKey)
			} else {
				color.Red("Could not parse keyword key %s. Got err: %s", fpath, err)
			}
		}
	case mode.IsRegular():
		color.Red("Error: '-key-dir' was given a file. Expected directory.")
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

			err = DecryptAndSavePatientFile(in, out, params, keywordKeys, freqOuterKey)
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
	// set procs -1
	runtime.GOMAXPROCS(runtime.NumCPU())

	// for pprof
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	// cli app
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
