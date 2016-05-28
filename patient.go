package main

import (
	"encoding/json"
	"io/ioutil"
)

//MARK: Encryption/Decryption

func ApplyCryptorToPatient(patient map[string]interface{}, cryptor func(interface{}) interface{}) map[string]interface{} {
	// car free text
	cardiacNotes, _ := patient["Car"].([]interface{})
	newCarNotes := make([]map[string]interface{}, len(cardiacNotes))
	for i := range cardiacNotes {
		note := cardiacNotes[i].(map[string]interface{})

		note["free_text"] = cryptor(note["free_text"])

		newCarNotes[i] = note
	}

	// lno free text
	lnoNotes, _ := patient["Lno"].([]interface{})
	newLnoNotes := make([]map[string]interface{}, len(lnoNotes))
	for i := range lnoNotes {
		note := lnoNotes[i].(map[string]interface{})
		note["free_text"] = cryptor(note["free_text"])
		newLnoNotes[i] = note
	}

	patient["Car"] = newCarNotes
	patient["Lno"] = newLnoNotes

	return patient
}

//MARK: io
func readPatientFile(filepath string) (patient map[string]interface{}, err error) {
	data, _ := ioutil.ReadFile(filepath)
	err = json.Unmarshal(data, &patient)

	return
}

func writePatient(patient map[string]interface{}, filepath string) (err error) {
	newPatientData, _ := json.Marshal(patient)
	err = ioutil.WriteFile(filepath, newPatientData, 0660)
	return
}
