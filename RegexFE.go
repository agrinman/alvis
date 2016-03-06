package alvis

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"

	"golang.org/x/crypto/bn256"
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
}

type MasterSecretKey struct {
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
	return Setup(N, Σ)
}

// Setup initializaes the MSK and PP
func Setup(n int, alphabet []rune) (MasterSecretKey, PublicParams, error) {

	return MasterSecretKey{}, PublicParams{}, nil
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
