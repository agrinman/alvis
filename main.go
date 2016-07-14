package main

import (
	"encoding/json"
	"fmt"
	"log"
	"path"
	"runtime"
	"unicode"

	"strings"

	"io/ioutil"
	"os"

	"github.com/agrinman/alvis/base36"
	"github.com/agrinman/alvis/freqFE"
	"github.com/agrinman/alvis/privKS"

	"github.com/fatih/color"
	"github.com/urfave/cli"

	"net/http"
	_ "net/http/pprof"
)

//MARK: Key types and parsing

type MasterKey struct {
	KeywordKey   privKS.MasterKey
	FrequencyKey freqFE.MasterKey
}

func parseMasterKey(filepath string) (msk MasterKey, err error) {
	mskBytes, err := ioutil.ReadFile(filepath)
	if err != nil {
		return
	}

	// unmarshall master secret
	err = json.Unmarshal(mskBytes, &msk)
	if err != nil {
		return
	}

	return
}

func parsePrivateKey(filepath string) (privateKey privKS.PrivateKey, err error) {
	kpBytes, err := ioutil.ReadFile(filepath)
	if err != nil {
		return
	}

	// unmarshall private key
	err = json.Unmarshal(kpBytes, &privateKey)

	return
}

func genMaster(c *cli.Context) (err error) {
	if c.NumFlags() < 1 {
		color.Red("Missing '-out' flag for filepath of master key")
		return
	}

	outPath := c.String("out")

	// setup frequency key
	freqMaster, err := freqFE.GenMasterKey()
	if err != nil {
		color.Red(err.Error())
		return
	}

	// setup ibe key
	keyMaster, err := privKS.GenMasterKey()
	if err != nil {
		color.Red(err.Error())
		return
	}
	msk := MasterKey{keyMaster, freqMaster}

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
		color.Red("Missing parameters: \n\t-msk for path to master secret key \n\t-words a file containing keywords on each file  \n\t-out-dir directory path where secret keys will be written to")
		return
	}

	// read master secret file
	mskPath := c.String("msk")

	master, err := parseMasterKey(mskPath)
	if err != nil {
		color.Red(err.Error())
		return
	}

	// get out path ready
	outPath := c.String("out-dir")
	os.MkdirAll(outPath, 0777)

	// gen secret key
	wordFile := c.String("words")
	words, err := ioutil.ReadFile(wordFile)
	if err != nil {
		color.Red(err.Error())
		return
	}

	// create sk for all the words
	for _, w := range strings.Split(string(words), "\n") {
		w = strings.TrimSpace(w)
		if len(w) == 0 {
			continue
		}

		secretKey := master.KeywordKey.Extract(w)

		outBytes, err := json.Marshal(secretKey)
		if err != nil {
			color.Red(err.Error())
			continue
		}

		fpath := path.Join(outPath, fmt.Sprintf("%s.sk", w))

		// write file
		err = ioutil.WriteFile(fpath, outBytes, 0660)
	}

	return
}

func genFrequencyKey(c *cli.Context) (err error) {
	if c.NumFlags() < 2 {
		color.Red("Missing one of: \n\t-msk for path to master secret key \n\t-out flag for filepath of search keyword secret key")
		return
	}

	// read master secret file
	mskPath := c.String("msk")

	master, err := parseMasterKey(mskPath)
	if err != nil {
		color.Red(err.Error())
		return
	}

	outBytes := master.FrequencyKey.OuterKey

	// get outPath
	outPath := c.String("out")

	// write file
	err = ioutil.WriteFile(outPath, outBytes, 0660)

	return
}

func encrypt(c *cli.Context) (err error) {
	if c.NumFlags() < 3 {
		color.Red("Missing one of: \n\t-msk for path to master secret key \n\t-patient-dir for directory of patient files \n\t-out-dir for the directory of the encrypted patient files")
		return
	}

	// read master secret file
	mskPath := c.String("msk")
	master, err := parseMasterKey(mskPath)
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

			err = EncryptAndSavePatientFile(in, out, master)
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
	if c.NumFlags() < 4 {
		color.Red("Missing one or more args: \n\t-key-dir for directory path to functional keys \n\t-freq-key for path to the frequency decryption key file \n\t-patient-dir for directory of patient files \n\t-out-dir for the where to write the partially-decrypted patient files")
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

	var keywordKeys []privKS.PrivateKey

	switch mode := fi.Mode(); {
	case mode.IsDir():
		files, _ := ioutil.ReadDir(keyDirPath)
		//read all keys
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
		color.Red("Error: '-key-dir' was given a file. Expected directory.")
		return
	}

	// get and mkdir out path
	outPath := c.String("out-dir")
	os.MkdirAll(outPath, 0777)

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

func decryptFreq(c *cli.Context) (err error) {
	if c.NumFlags() < 2 {
		color.Red("Missing one of: \n\t-msk for path to master secret key \n\t-c frequency cipher-text \n\t-file multiple frequency cipher-texts in a file")
		return
	}

	// read master secret file
	mskPath := c.String("msk")
	master, err := parseMasterKey(mskPath)
	if err != nil {
		color.Red(err.Error())
		return
	}

	// try if many
	filePath := c.String("file")
	if filePath != "" {
		fileBytes, fileErr := ioutil.ReadFile(filePath)
		if fileErr != nil {
			err = fileErr
			color.Red(err.Error())
			return
		}

		fileCopy := string(fileBytes)

		splitter := func(c rune) bool {
			return !unicode.IsLetter(c) && !unicode.IsNumber(c)
		}
		tokens := strings.FieldsFunc(fileCopy, splitter)

		for _, t := range tokens {
			ctxt, decodeErr := base36.DecodeString(t)
			if decodeErr != nil {
				continue
			}

			ptxt, decryptErr := freqFE.DecryptInner(master.FrequencyKey, ctxt)
			fmt.Println(ptxt)
			if decryptErr != nil {
				continue
			}

			fileCopy = strings.Replace(fileCopy, t, string(ptxt), -1)
		}

		fmt.Println(fileCopy)

		return
	}

	// otherwise just decrypt one
	// get and mkdir out path
	ctxt, err := base36.DecodeString(c.String("c"))
	if err != nil {
		color.Red(err.Error())
		return
	}

	ptxt, err := freqFE.DecryptInner(master.FrequencyKey, ctxt)
	if err != nil {
		color.Red(err.Error())
		return
	}

	fmt.Println(string(ptxt))
	return
}

//MARK: old main
func calcStats(c *cli.Context) (err error) {
	if c.NumFlags() < 1 {
		color.Red("Missing parameter: \n\t-patient-dir for path to patient files")
		return
	}

	patientFiles, err := getFilePathsIn(c.String("patient-dir"))
	if err != nil {
		color.Red(err.Error())
		return
	}

	totalCount := 0
	for _, pf := range patientFiles {
		var patient map[string]interface{}
		patient, err = readPatientFile(pf)
		if err != nil {
			color.Red(err.Error())
			continue
		}

		// car free text
		cardiacNotes, _ := patient["Car"].([]interface{})
		carNoteCount := 0

		for i := range cardiacNotes {
			note := cardiacNotes[i].(map[string]interface{})
			carNoteCount += len(SplitFreeText(note["free_text"].(string)))
		}

		// lno free text
		lnoNotes, _ := patient["Lno"].([]interface{})
		lnoNoteCount := 0
		for i := range lnoNotes {
			note := lnoNotes[i].(map[string]interface{})
			lnoNoteCount += len(SplitFreeText(note["free_text"].(string)))
		}

		color.Green("-- stats on %s --", pf)
		fmt.Printf("- #Car words: %d\n", carNoteCount)
		fmt.Printf("- #Lno words: %d\n", lnoNoteCount)
		fmt.Printf("- Word Total: %d\n", carNoteCount+lnoNoteCount)

		totalCount += carNoteCount + lnoNoteCount

	}

	color.Magenta("--- overall stats ---")
	fmt.Printf("%d words for searchable encryption\n", totalCount)

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
						cli.StringFlag{Name: "words"},
						cli.StringFlag{Name: "msk"},
						cli.StringFlag{Name: "out-dir"},
					},
				},
				{
					Name:   "frequency",
					Usage:  "functional key for computing frequency count",
					Action: genFrequencyKey,
					Flags: []cli.Flag{
						cli.StringFlag{Name: "msk"},
						cli.StringFlag{Name: "out"},
					},
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
		{
			Name:    "decrypt-freq",
			Aliases: []string{"df"},
			Usage:   "Decrypt a frequency ciphertext",
			Action:  decryptFreq,
			Flags: []cli.Flag{
				cli.StringFlag{Name: "msk"},
				cli.StringFlag{Name: "c"},
				cli.StringFlag{Name: "file"},
			},
		},
		{
			Name:    "stats",
			Aliases: nil,
			Usage:   "Calculate the number of words in patient files",
			Action:  calcStats,
			Flags: []cli.Flag{
				cli.StringFlag{Name: "patient-dir"},
			},
		},
	}

	app.Run(os.Args)
}
