package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"
	"sync"
	"unicode"

	"github.com/agrinman/alvis/ibe"

	"github.com/fatih/color"
)

//MARK: Encryption/Decryption
func EncryptAndSavePatientFile(inpath string, outpath string, master ibe.MasterKey, freq FreqFEMasterKey) (err error) {
	patient, err := readPatientFile(inpath)
	encryptedPatient := ApplyCryptorToPatient(patient, func(freeText interface{}) interface{} {

		tokens := SplitFreeText(freeText.(string))
		numTokens := len(tokens)
		color.Yellow("Begining KeywordFE Encryption with %d tokens...", numTokens)

		encryptedKeywordFETokens := make([]ibe.CipherTextSerialized, numTokens)
		var wg sync.WaitGroup
		wg.Add(numTokens)
		for i, t := range tokens {
			go func(w *sync.WaitGroup, i int, t string) {
				encryptedKeywordFETokens[i], err = ibe.MarshallCipherText(master.Params, master.Params.EncryptKeyword(t))
				if err != nil {
					fmt.Println("Found error while encrypting/serializing keyword: ", err)
				}
				w.Done()
			}(&wg, i, t)
		}
		wg.Wait()

		color.Yellow("Done with %d", len(tokens))

		encryptedFreqFETokens := make([]string, len(tokens))

		for i := range tokens {
			res, resErr := EncryptInnerOuter(freq, []byte(tokens[i]))
			if resErr != nil {
				return resErr
			}
			encryptedFreqFETokens[i] = base64.StdEncoding.EncodeToString(res)
		}

		resultMap := make(map[string]interface{})
		resultMap["keyword_enc"] = encryptedKeywordFETokens
		resultMap["frequency_enc"] = encryptedFreqFETokens

		return resultMap
	})

	err = writePatient(encryptedPatient, outpath)
	return
}

func DecryptAndSavePatientFile(inpath string, outpath string, keywordKeys []ibe.PrivateKey, freqOuter []byte) (err error) {
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
		return !unicode.IsLetter(c) && !unicode.IsNumber(c) && c != '_'
	}
	return strings.FieldsFunc(text, splitter)
}

// parse helper
func ApplyCryptorToPatient(patient map[string]interface{}, cryptor func(interface{}) interface{}) map[string]interface{} {

	// car free text
	cardiacNotes, _ := patient["Car"].([]interface{})
	newCarNotes := make([]map[string]interface{}, len(cardiacNotes))

	// lno free text
	lnoNotes, _ := patient["Lno"].([]interface{})
	newLnoNotes := make([]map[string]interface{}, len(lnoNotes))

	// var wg sync.WaitGroup
	// wg.Add(len(cardiacNotes) + len(lnoNotes))

	for i := range cardiacNotes {
		note := cardiacNotes[i].(map[string]interface{})
		note["free_text"] = cryptor(note["free_text"])
		newCarNotes[i] = note

		// go func(w *sync.WaitGroup, i int, note map[string]interface{}) {
		// 	note["free_text"] = cryptor(note["free_text"])
		// 	newCarNotes[i] = note
		// 	w.Done()
		// }(&wg, i, note)
	}

	for i := range lnoNotes {
		note := lnoNotes[i].(map[string]interface{})
		note["free_text"] = cryptor(note["free_text"])
		newLnoNotes[i] = note

		// go func(w *sync.WaitGroup, i int, note map[string]interface{}) {
		// 	note["free_text"] = cryptor(note["free_text"])
		// 	newLnoNotes[i] = note
		// 	w.Done()
		// }(&wg, i, note)
	}
	// wg.Wait()

	patient["Car"] = newCarNotes
	patient["Lno"] = newLnoNotes

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

//MARK: old main
func oldmain() {
	patient, _ := readPatientFile("patients/test.json")

	// car free text
	cardiacNotes, _ := patient["Car"].([]interface{})
	wordCount := 0

	for i := range cardiacNotes {
		note := cardiacNotes[i].(map[string]interface{})

		toks := SplitFreeText(note["free_text"].(string))
		for _, t := range toks {
			if _, err := strconv.Atoi(t); err == nil {
				continue
			}
			wordCount += 1
		}
	}

	// lno free text
	lnoNotes, _ := patient["Lno"].([]interface{})

	for i := range lnoNotes {
		note := lnoNotes[i].(map[string]interface{})
		toks := SplitFreeText(note["free_text"].(string))
		for _, t := range toks {
			if _, err := strconv.Atoi(t); err == nil {
				continue
			}
			wordCount += 1
		}
	}

	fmt.Println("number of tokens (ints excluded) in a patient file: ", wordCount)
}
