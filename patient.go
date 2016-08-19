package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"sync"
	"unicode"

	"github.com/agrinman/alvis/base36"
	"github.com/agrinman/alvis/pfs"
	"github.com/agrinman/alvis/pks"

	"github.com/fatih/color"
)

var (
	recordTypes = []string{"Car", "Lno", "Dis", "Mic", "Opn", "Pat", "Rad"}
)

//MARK: Encryption/Decryption
func EncryptAndSavePatientFile(inpath string, outpath string, master MasterKey) (err error) {
	patient, err := readPatientFile(inpath)
	encryptedPatient := ApplyCryptorToPatient(patient, func(freeText interface{}) interface{} {

		tokens := SplitFreeText(freeText.(string))
		numTokens := len(tokens)

		encryptedKeywordFETokens := make([]string, numTokens)
		for i, t := range tokens {
			ctxtBytes, errEnc := master.KeywordKey.Hide(t)
			if errEnc != nil {
				color.Red("Found error while encrypting/serializing keyword: ", errEnc)
			}

			var errEncode error
			encryptedKeywordFETokens[i], errEncode = base36.Encode(ctxtBytes)
			if errEncode != nil {
				color.Red("Found error while encoding keyword: ", errEncode)
			}

		}

		encryptedFreqFETokens := make([]string, len(tokens))

		for i := range tokens {
			res, resErr := pfs.Disguise(master.FrequencyKey, []byte(tokens[i]))
			if resErr != nil {
				return resErr
			}
			var errEncode error
			encryptedFreqFETokens[i], errEncode = base36.Encode(res.Hidden)
			if errEncode != nil {
				color.Red("Found error while encoding keyword: ", errEncode)
			}

		}

		resultMap := make(map[string]interface{})
		resultMap["keyword_enc"] = encryptedKeywordFETokens
		resultMap["frequency_enc"] = encryptedFreqFETokens

		return resultMap
	})

	err = writePatient(encryptedPatient, outpath)
	return
}

func DecryptAndSavePatientFile(inpath string, outpath string, keywordKeys []pks.PrivateKey, freqOuter []byte) (err error) {

	patient, err := readPatientFile(inpath)

	stats := make(map[string]int)
	statsMutex := &sync.Mutex{}
	decryptedPatient := ApplyCryptorToPatient(patient, func(encryptedMap interface{}) interface{} {

		inMap, ok := encryptedMap.(map[string]interface{})
		if !ok {
			fmt.Println("Unexpected type: ", encryptedMap)
		}

		encryptedKeywordFETokens := inMap["keyword_enc"].([]interface{})
		encryptedFreqFETokens := inMap["frequency_enc"].([]interface{})

		if len(encryptedFreqFETokens) != len(encryptedKeywordFETokens) {
			color.Red("Fatal: Keyword / Frequency encrypted token lists have different lengths.")
			os.Exit(2)
		}

		//numTokens := len(encryptedFreqFETokens)

		decryptedTokens := make([]string, len(encryptedFreqFETokens))

		for i, t := range encryptedFreqFETokens {
			tbytes, errDecode := base36.DecodeString(t.(string))
			if errDecode != nil {
				color.Red("Cannot decode (1): %s. Error: %s", t.(string), errDecode)
				continue
			}

			decryptedToken, errDecr := pfs.Recognize(freqOuter, tbytes)
			if errDecr != nil {
				color.Red("Cannot decrypt bytes: %d", tbytes)
				continue
			}

			var errEncode error
			decryptedTokens[i], errEncode = base36.Encode(decryptedToken)
			if errEncode != nil {
				color.Red("Found error while encoding keyword: ", errEncode)
			}

		}

		// next do keyword fe decryptions
		for i, ctxtString := range encryptedKeywordFETokens {
			ctxt, errDecode := base36.DecodeString(ctxtString.(string))
			if errDecode != nil {
				color.Red("Cannot decode cipher text: %s. Error: ", ctxt, errDecode)
			}
			for _, sk := range keywordKeys {
				if sk.Check(ctxt) {
					statsMutex.Lock()
					stats[sk.Keyword] += 1
					statsMutex.Unlock()

					//color.Magenta("Decrypted keyword successfully: %s", sk.Keyword)
					decryptedTokens[i] = sk.Keyword
				}
			}
		}

		return strings.Join(decryptedTokens, " ")
	})

	color.Green("-- stats on %s --", inpath)
	printStats(stats)

	err = writePatient(decryptedPatient, outpath)
	return
}

//MARK: Free text helpers
func SplitFreeText(text string) []string {
	// cleanup
	filteredText := strings.Replace(text, "\\r", " ", -1)
	filteredText = strings.Replace(filteredText, "\\n", " ", -1)
	filteredText = strings.ToLower(filteredText)

	// split
	splitter := func(c rune) bool {
		return !unicode.IsLetter(c) &&
			!unicode.IsNumber(c) &&
			c != '_' &&
			c != '\'' &&
			c != '"' &&
			c != '%'
	}

	return strings.FieldsFunc(filteredText, splitter)
}

// parse helper
func ApplyCryptorToPatient(patient map[string]interface{}, cryptor func(interface{}) interface{}) map[string]interface{} {

	var wg sync.WaitGroup
	for _, record := range recordTypes {
		notes, _ := patient[record].([]interface{})
		newNote := make([]map[string]interface{}, len(notes))

		wg.Add(len(notes))

		for i := range notes {
			note := notes[i].(map[string]interface{})
			go func(w *sync.WaitGroup, i int, note map[string]interface{}) {
				note["free_text"] = cryptor(note["free_text"])
				newNote[i] = note
				w.Done()
			}(&wg, i, note)
		}

		patient[record] = newNote
	}
	wg.Wait()

	return patient
}

//MARK: patient io
func readPatientFile(filepath string) (patient map[string]interface{}, err error) {
	data, _ := ioutil.ReadFile(filepath)
	err = json.Unmarshal(data, &patient)
	return
}

func writePatient(patient map[string]interface{}, filepath string) (err error) {
	newPatientData, _ := json.MarshalIndent(patient, "", "    ")
	err = ioutil.WriteFile(filepath, newPatientData, 0660)
	return
}

// MARK: stats

func printStats(stats map[string]int) {
	for w, c := range stats {
		fmt.Printf("- %s: %d\n", color.YellowString(w), c)
	}
}

//MARK: old main
func oldmain() {
	patient, _ := readPatientFile("tmp/patients/patient_1.json")

	// car free text
	cardiacNotes, _ := patient["Car"].([]interface{})
	wordCount := 0

	for i := range cardiacNotes {
		note := cardiacNotes[i].(map[string]interface{})

		toks := SplitFreeText(note["free_text"].(string))
		if i == 0 {
			l, _ := json.Marshal(toks)
			fmt.Println(string(l))
		}
		for _ = range toks {
			wordCount += 1
		}
	}

	// lno free text
	lnoNotes, _ := patient["Lno"].([]interface{})

	for i := range lnoNotes {
		note := lnoNotes[i].(map[string]interface{})
		toks := SplitFreeText(note["free_text"].(string))
		for _ = range toks {
			wordCount += 1
		}
	}

	fmt.Println("number of tokens in a patient file: ", wordCount)
}
