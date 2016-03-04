package alvis

// Transition is the tuple of X -> Y on input C
type Transition struct {
    X int
    Y int
    C string
}
// DFA is a Deterministic Finite Automaton
type DFA struct {
    Representation string
    States  []int
    Alphabet []string
    Transitions [][][]int
    Start int
    AcceptStates []int
}

// GenDFA takes a regex string and outputs a DFA
func GenDFA(regex string) DFA {
    
}


