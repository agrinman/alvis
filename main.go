package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
)

func newmain() {
	// parse test.json
	data, _ := ioutil.ReadFile("test.json")

	var patient map[string]interface{}
	_ = json.Unmarshal(data, &patient)

	// car free text
	cardiacNotes, _ := patient["Car"].([]interface{})
	newCarNotes := make([]map[string]interface{}, len(cardiacNotes))
	for i := range cardiacNotes {
		fmt.Println("CAR ----> ", i)
		note := cardiacNotes[i].(map[string]interface{})
		note["free_text"] = SplitFreeText(note["free_text"].(string))

		newCarNotes[i] = note
	}

	// lno free text
	lnoNotes, _ := patient["Lno"].([]interface{})
	newLnoNotes := make([]map[string]interface{}, len(lnoNotes))
	for i := range lnoNotes {
		fmt.Println("LNO ----> ", i)
		note := lnoNotes[i].(map[string]interface{})
		note["free_text"] = SplitFreeText(note["free_text"].(string))

		fmt.Println(note)
		newLnoNotes[i] = note
	}

	patient["Car"] = newCarNotes
	patient["Lno"] = newLnoNotes

	newPatientData, _ := json.Marshal(patient)
	ioutil.WriteFile("test.json.enc", newPatientData, 0660)
}
