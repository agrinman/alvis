package alvis

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"golang.org/x/crypto/bn256"
	"math/big"
)

//////////////////////////////////////////////
//MARK: Default Contants
/////////////////////////////////////////////

const (
	N = 128
)

var (
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

type PublicParams struct {
	G, Z, Hs, He *bn256.G1
	H            map[rune]*bn256.G1
	E            *bn256.GT
}

type MasterSecretKey struct {
	D *big.Int
}

type SecretKey struct {
}

type CipherText struct {
}

//////////////////////////////////////////////
//MARK: Setup, KeyGen, Encrypt, Decrypt
/////////////////////////////////////////////

// DefaultSetup runs Setup with default inputs
func DefaultSetup() (MasterSecretKey, PublicParams, error) {
	return Setup(Σ)
}

// Setup initializaes the MSK and PP
func Setup(alphabet []rune) (MasterSecretKey, PublicParams, error) {
	msk := MasterSecretKey{}
	pp := PublicParams{}

	// gen random g, z, hStart, hEnd from G
	_, g, err := bn256.RandomG1(rand.Reader)
	if err != nil {
		return msk, pp, err
	}
	_, z, err := bn256.RandomG1(rand.Reader)
	if err != nil {
		return msk, pp, err
	}
	_, hStart, err := bn256.RandomG1(rand.Reader)
	if err != nil {
		return msk, pp, err
	}
	_, hEnd, err := bn256.RandomG1(rand.Reader)
	if err != nil {
		return msk, pp, err
	}

	// gen random v for each char in alphabet
	hMap := make(map[rune]*bn256.G1)
	for _, c := range alphabet {
		_, v, err := bn256.RandomG1(rand.Reader)
		if err != nil {
			return msk, pp, err
		}

		hMap[c] = v
	}

	// gen random alpha from Zp
	a, err := random()
	if err != nil {
		return msk, pp, err
	}

	pp.G = g
	pp.Z = z
	pp.Hs = hStart
	pp.He = hEnd
	pp.H = hMap

	pp.E = bn256.Pair(g, g)
	// Creat the secret

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

//////////////////////////////////////////////
// MARK: Helpers
// FROM: https://golang.org/x/crypto/bn256
/////////////////////////////////////////////

// random returns a positive integer in the range [1, bn256.Order)
// (denoted by Zp in http://crypto.stanford.edu/~dabo/papers/bbibe.pdf).
//
// The paper refers to random numbers drawn from Zp*. From a theoretical
// perspective, the uniform distribution over Zp and Zp* start within a
// statistical distance of 1/p (where p=bn256.Order is a ~256bit prime).  Thus,
// drawing uniformly from Zp is no different from Zp*.
func random() (*big.Int, error) {
	for {
		k, err := rand.Int(rand.Reader, bn256.Order)
		if err != nil {
			return nil, err
		}
		if k.Sign() > 0 {
			return k, nil
		}
	}
}

// Hash a particular message with the given prefix. Specifically, this computes
// SHA256(prefix || data) where prefix is a fixed-length string.
func hashval(prefix [1]byte, data []byte) *[sha256.Size]byte {
	hasher := sha256.New()
	hasher.Write(prefix[:])
	hasher.Write(data)

	var ret [sha256.Size]byte
	copy(ret[:], hasher.Sum(nil))

	return &ret
}

// Hashes a value SHA256(prefix || data) where prefix is a fixed-length
// string.  The hashed value is then converted  to a value modulo the group order.
func val2bignum(prefix [1]byte, data []byte) *big.Int {
	k := new(big.Int).SetBytes(hashval(prefix, data)[:])
	return k.Mod(k, bn256.Order)
}

// marshalG1 writes the marshaled form of g into dst.
func marshalG1(dst []byte, g *bn256.G1) error {
	src := g.Marshal()
	if len(src) != len(dst) {
		return fmt.Errorf("bn256.G1.Marshal returned a %d byte slice, expected %d: the BB1 IBE implementation is likely broken", len(src), len(dst))
	}
	copy(dst, src)
	return nil
}
