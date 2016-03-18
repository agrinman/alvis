package main

import (
	"fmt"
	"os"
	"testing"
)

// TestMain setup
func TestMain(m *testing.M) {
	os.Exit(m.Run())
}

func sampleDFA() DFA {
	// return a DFA that accepts 2 a's and 2 or b's
	M := DFA{
		Representation: "aabb+",
		States:         []State{0, 1, 2, 3, 4},
		Alphabet:       []rune{'a', 'b'},
		Transitions: []Transition{
			Transition{0, 1, 'a', 0},
			Transition{1, 2, 'a', 1},
			Transition{2, 3, 'b', 2},
			Transition{3, 4, 'b', 3},
			Transition{4, 4, 'b', 4},
		},
		Start:        0,
		AcceptStates: []State{4},
	}

	tMap := make(map[State]map[rune]Transition)

	for _, t := range M.Transitions {
		tMap[t.X] = make(map[rune]Transition)
		tMap[t.X][t.C] = t
	}
	M.TransitionMap = tMap

	return M
}

// TestGenAndEval tests functionality
func TestEncryptDecrypt(t *testing.T) {
	msk, pp, err := DefaultSetup()
	if err != nil {
		t.Error(err)
		return
	}

	fmt.Println("")

	dfa := sampleDFA()
	sk, err := msk.KeyGen(dfa)
	if err != nil {
		t.Error(err)
		return
	}

	ct, err := pp.Encrypt("aabbb", []byte{0x01})
	if err != nil {
		t.Error(err)
		return
	}

	m, err := pp.Decrypt(sk, ct)
	if err != nil {
		t.Error(err)
		return
	}

	if m[0] != 0x01 {
		t.Error("message invalid, got: ", m)
	}
}
