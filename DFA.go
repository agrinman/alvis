package main

// Transition is the tuple of X -> Y on input C
type Transition struct {
	X State
	Y State
	C rune
}

// State represents the state id as an int
type State int

// DFA is a Deterministic Finite Automaton
type DFA struct {
	Representation string
	States         []State
	Alphabet       []rune
	Transitions    []Transition
	TransitionMap  map[State]map[State]int
	Start          State
	AcceptStates   []State
}

// GenDFA takes a regex string and outputs a DFA
func GenDFA(regex string) DFA {
	return DFA{}
}
