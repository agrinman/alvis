package main

import (
	"github.com/Nik-U/pbc"
)

//////////////////////////////////////////////
//MARK: Default Contants
// To be secure, generic discrete log algorithms must be infeasible in groups of order r,
// and finite field discrete log algorithms must be infeasible in groups of order q^2.
/////////////////////////////////////////////

const (
	// R is the order...
	R = 160

	// Q is the bitlen of a prime for field F_q for some prime q = 3 mod 4
	Q = 512
)

var (
	// Σ is the default alphabet for the DFA
	Σ = []rune{
		'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
		'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
		':', ';', '\'', '"', '%', '-', '^', '@', '+', '-', '#', '&', '&',
		'|', '\\', '(', ')', '[', ']', '{', '}', '`', '~', '=', '_',
	}
)

//////////////////////////////////////////////
//MARK: PP, MSK, SK CT
/////////////////////////////////////////////

// PublicParams are the system parameters
type PublicParams struct {
	G, Z, Hs, He *pbc.Element
	H            map[rune]*pbc.Element
	E            *pbc.Element
	Params       *pbc.Params
}

// MasterSecretKey is msk
type MasterSecretKey struct {
	PublicKey PublicParams
	D         *pbc.Element
}

// SecretKey is sk
type SecretKey struct {
	M      DFA
	Kstart elementDouble
	K      map[Transition]elementTriple
	Kend   map[State]elementDouble
}

type elementDouble struct {
	E1 *pbc.Element
	E2 *pbc.Element
}

type elementTriple struct {
	E1 *pbc.Element
	E2 *pbc.Element
	E3 *pbc.Element
}

// CipherText is ct
type CipherText struct {
	Cm     *pbc.Element
	Cstart elementDouble
	Cend   elementDouble

	C []elementDouble
}

//////////////////////////////////////////////
//MARK: Setup, KeyGen, Encrypt, Decrypt
/////////////////////////////////////////////

// DefaultSetup runs Setup with default inputs
func DefaultSetup() (MasterSecretKey, PublicParams, error) {
	return Setup(R, Q, Σ)
}

// Setup initializaes the MSK and PP
func Setup(r uint32, q uint32, alphabet []rune) (MasterSecretKey, PublicParams, error) {
	pbc.SetCryptoRandom()

	msk := MasterSecretKey{}
	pp := PublicParams{}

	pp.Params = pbc.GenerateA(r, q)

	pairing := pp.Params.NewPairing()

	g := pairing.NewG1().Rand()
	z := pairing.NewG1().Rand()
	hStart := pairing.NewG1().Rand()
	hEnd := pairing.NewG1().Rand()

	// gen random v for each char in alphabet
	hMap := make(map[rune]*pbc.Element)
	for _, c := range alphabet {
		hMap[c] = pairing.NewG1().Rand()
	}

	// gen random alpha from Zp
	a := pairing.NewZr().Rand()

	// set PP
	pp.G = g
	pp.Z = z
	pp.Hs = hStart
	pp.He = hEnd
	pp.H = hMap

	pairGG := pairing.NewGT().Pair(g, g)
	pp.E = pairing.NewGT().PowZn(pairGG, a)

	// give the msk the pp
	msk.PublicKey = pp

	// Create the master secret g^(-a)
	aInv := pairing.NewZr().Invert(a)
	msk.D = pairing.NewG1().PowZn(g, aInv)

	return msk, pp, nil
}

// KeyGen generates a secret key from a dfa and msk
func (msk MasterSecretKey) KeyGen(dfa DFA) (SecretKey, error) {
	pbc.SetCryptoRandom()

	sk := SecretKey{}

	pairing := msk.PublicKey.Params.NewPairing()

	D := make(map[State]*pbc.Element)
	for _, q := range dfa.States {
		D[q] = pairing.NewG1().Rand()
	}

	rTs := make([]*pbc.Element, len(dfa.Transitions))
	for i := range dfa.Transitions {
		rTs[i] = pairing.NewZr().Rand()
	}
	rStart := pairing.NewZr().Rand()

	rEnds := make([]*pbc.Element, len(dfa.AcceptStates))
	for i := range dfa.AcceptStates {
		rEnds[i] = pairing.NewZr().Rand()
	}

	// create the key
	ks1 := pairing.NewG1().Mul(D[dfa.Start], pairing.NewG1().PowZn(msk.PublicKey.Hs, rStart))
	ks2 := pairing.NewG1().PowZn(msk.PublicKey.G, rStart)
	sk.Kstart = elementDouble{E1: ks1, E2: ks2}

	sk.K = make(map[Transition]elementTriple)

	for i, t := range dfa.Transitions {
		k1 := pairing.NewG1().Mul(pairing.NewG1().Invert(D[t.X]), pairing.NewG1().PowZn(msk.PublicKey.Z, rTs[i]))
		k2 := pairing.NewG1().PowZn(msk.PublicKey.G, rTs[i])
		k3 := pairing.NewG1().Mul(pairing.NewG1().Invert(D[t.Y]), pairing.NewG1().PowZn(msk.PublicKey.H[t.C], rTs[i]))

		sk.K[t] = elementTriple{E1: k1, E2: k2, E3: k3}
	}

	sk.Kend = make(map[State]elementDouble)

	for i, q := range dfa.AcceptStates {
		ke1 := pairing.NewG1().Mul(msk.D, pairing.NewG1().Mul(D[q], pairing.NewG1().PowZn(msk.PublicKey.He, rEnds[i])))
		ke2 := pairing.NewG1().PowZn(msk.PublicKey.G, rEnds[i])

		sk.Kend[q] = elementDouble{E1: ke1, E2: ke2}
	}

	return sk, nil
}

// Encrypt a word w with message m, under public params
func (p PublicParams) Encrypt(w string, m []byte) (CipherText, error) {
	pbc.SetCryptoRandom()

	ct := CipherText{}
	pairing := p.Params.NewPairing()
	L := len(w)

	// generare random sl
	sl := make([]*pbc.Element, L+1)
	for i := 0; i < L+1; i++ {
		sl[i] = pairing.NewZr().Rand()
	}

	// set Cm
	mG := pairing.NewGT().SetBytes(m)
	ct.Cm = pairing.NewGT().Mul(mG, pairing.NewGT().PowZn(p.E, sl[L]))

	// set Cstart
	cs1 := pairing.NewG1().PowZn(p.G, sl[0])
	cs2 := pairing.NewG1().PowZn(p.Hs, sl[0])
	ct.Cstart = elementDouble{E1: cs1, E2: cs2}

	// set C
	runes := []rune(w)
	ct.C = make([]elementDouble, L)
	for i := 1; i < L; i++ {
		c1 := pairing.NewG1().PowZn(p.G, sl[i])
		c2 := pairing.NewG1().Mul(
			pairing.NewG1().PowZn(p.H[runes[i]], sl[i]),
			pairing.NewG1().PowZn(p.Z, sl[i-1]),
		)

		ct.C[i] = elementDouble{c1, c2}

	}

	// set Cend
	ce1 := pairing.NewG1().PowZn(p.G, sl[L])
	ce2 := pairing.NewG1().PowZn(p.He, sl[L])
	ct.Cend = elementDouble{ce1, ce2}

	return ct, nil
}

// Decrypt a ciphertext using the secret key
func (p PublicParams) Decrypt(sk SecretKey, ct CipherText) ([]byte, error) {
	pbc.SetCryptoRandom()

	pairing := p.Params.NewPairing()
	L := len(ct.C) - 1

	B := make([]*pbc.Element, L+1)

	// compute B[0]
	B[0] = pairing.NewGT().Mul(
		pairing.NewGT().Pair(ct.Cstart.E1, sk.Kstart.E1),
		pairing.NewGT().Invert(pairing.NewGT().Pair(ct.Cstart.E2, sk.Kstart.E2)),
	)

	// compute B

	for i := 1; i < len(ct.C); i++ {
		//ti := sk.M.TransitionMap[]
		//mul1 := pairing.NewGT().Mul(B[i-1], pairing.NewGT().Pair(ct.C[i-1].E1, y *pbc.Element))

	}

	return []byte{}, nil
}
