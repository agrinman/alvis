package alvis

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
	D *pbc.Element
}

// SecretKey is sk
type SecretKey struct {
}

// CipherText is ct
type CipherText struct {
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

	// Create the master secret g^(-a)
	aInv := pairing.NewZr().Invert(a)
	msk.D = pairing.NewG1().PowZn(g, aInv)

	return msk, pp, nil
}

// KeyGen generates a secret key from a dfa and msk
func (msk MasterSecretKey) KeyGen(dfa DFA) (SecretKey, error) {
	return SecretKey{}, nil
}

// Encrypt a word w with message m, under public params
func (p PublicParams) Encrypt(w string, m []byte) (CipherText, error) {

	return CipherText{}, nil
}

// Decrypt a ciphertext using the secret key
func (sk SecretKey) Decrypt(ct CipherText) ([]byte, error) {
	return []byte{}, nil
}
