package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"unicode"

	"github.com/agrinman/alvis/aesutil"
	"github.com/agrinman/alvis/freqFE"
	"github.com/agrinman/alvis/privKS"

	"github.com/fatih/color"
)

//MARK: Encryption/Decryption
func EncryptAndSavePatientFile(inpath string, outpath string, master MasterKey) (err error) {
	patient, err := readPatientFile(inpath)
	encryptedPatient := ApplyCryptorToPatient(patient, func(freeText interface{}) interface{} {

		tokens := SplitFreeText(freeText.(string))
		numTokens := len(tokens)
		color.Yellow("Begining KeywordFE Encryption with %d tokens...", numTokens)

		encryptedKeywordFETokens := make([]string, numTokens)
		for i, t := range tokens {
			ctxtBytes, errEnc := master.KeywordKey.EncryptKeyword(t)
			if errEnc != nil {
				fmt.Println("Found error while encrypting/serializing keyword: ", errEnc)
			}

			encryptedKeywordFETokens[i] = base64.URLEncoding.EncodeToString(ctxtBytes)
		}

		color.Yellow("Done with %d", len(tokens))

		encryptedFreqFETokens := make([]string, len(tokens))

		for i := range tokens {
			res, resErr := freqFE.EncryptInnerOuter(master.FrequencyKey, []byte(tokens[i]))
			if resErr != nil {
				return resErr
			}
			encryptedFreqFETokens[i] = base64.URLEncoding.EncodeToString(res)
		}

		resultMap := make(map[string]interface{})
		resultMap["keyword_enc"] = encryptedKeywordFETokens
		resultMap["frequency_enc"] = encryptedFreqFETokens

		return resultMap
	})

	err = writePatient(encryptedPatient, outpath)
	return
}

func DecryptAndSavePatientFile(inpath string, outpath string, keywordKeys []privKS.PrivateKey, freqOuter []byte) (err error) {

	patient, err := readPatientFile(inpath)
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

		numTokens := len(encryptedFreqFETokens)

		// run in parallel
		// var wg sync.WaitGroup
		// wg.Add(2 * numTokens)

		// start by decrypting freq enc first

		decryptedTokens := make([]string, len(encryptedFreqFETokens))

		for i, t := range encryptedFreqFETokens {
			// go func(w *sync.WaitGroup, i int, t string) {
			tbytes, errB64 := base64.URLEncoding.DecodeString(t.(string))
			if errB64 != nil {
				color.Red("Cannot decode base64: %s", t)
			}

			decryptedToken, errDecr := aesutil.AESDecrypt(freqOuter, tbytes)
			if errDecr != nil {
				color.Red("Cannot decrypt bytes: %d", tbytes)
			}

			decryptedTokens[i] = base64.URLEncoding.EncodeToString(decryptedToken)
			// 	w.Done()
			// }(&wg, i, t)
		}

		color.Yellow("Frequency phase done: %d tokens.", numTokens)

		// next do keyword fe decryptions
		color.Yellow("Begining KeywordFE Decryption with %d tokens...", numTokens)

		for i, ctxtString := range encryptedKeywordFETokens {
			// go func(w *sync.WaitGroup, i int, ctxtString string) {

			ctxt, errDecode := base64.URLEncoding.DecodeString(ctxtString.(string))
			if errDecode != nil {
				color.Red("Cannot decode cipher text: %s. Error: ", ctxt, errDecode)
				// w.Done()
				// return
			}
			for _, sk := range keywordKeys {
				//fmt.Println("ctxt: ", ctxtString)
				if sk.DecryptAndCheck(ctxt) {
					color.Magenta("Decrypted keyword successfully: %s", sk.Keyword)
					decryptedTokens[i] = sk.Keyword
				}
			}
			// 	w.Done()
			// }(&wg, i, ctxtString)
		}
		// wg.Wait()

		color.Yellow("Done Keyword Decryption Phase for %d tokens.", numTokens)
		return strings.Join(decryptedTokens, " ")
	})

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

	fmt.Println(len(cardiacNotes) + len(lnoNotes))
	//	var wg sync.WaitGroup
	//	wg.Add(len(cardiacNotes) + len(lnoNotes))

	for i := range cardiacNotes {
		note := cardiacNotes[i].(map[string]interface{})
		//	go func(w *sync.WaitGroup, i int, note map[string]interface{}) {
		note["free_text"] = cryptor(note["free_text"])
		newCarNotes[i] = note
		//		w.Done()
		//	}(&wg, i, note)
	}

	for i := range lnoNotes {
		note := lnoNotes[i].(map[string]interface{})
		//	go func(w *sync.WaitGroup, i int, note map[string]interface{}) {
		note["free_text"] = cryptor(note["free_text"])
		newLnoNotes[i] = note
		//		w.Done()
		//	}(&wg, i, note)
	}
	//wg.Wait()

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
