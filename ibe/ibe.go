package ibe

import (
	"crypto/sha256"

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

type MasterKey struct {
	W  *pbc.Element
	T1 *pbc.Element
	T2 *pbc.Element
	T3 *pbc.Element
	T4 *pbc.Element

	Params PublicParams
}

type PublicParams struct {
	Params  *pbc.Params
	R, Q    int
	Pairing *pbc.Pairing

	O *pbc.Element

	G  *pbc.Element
	G0 *pbc.Element
	G1 *pbc.Element

	V1 *pbc.Element
	V2 *pbc.Element
	V3 *pbc.Element
	V4 *pbc.Element
}

type PrivateKey struct {
	D0 *pbc.Element
	D1 *pbc.Element
	D2 *pbc.Element
	D3 *pbc.Element
	D4 *pbc.Element
}

type CipherText struct {
	C *pbc.Element

	C0 *pbc.Element
	C1 *pbc.Element
	C2 *pbc.Element
	C3 *pbc.Element
	C4 *pbc.Element
}

//MARK: IBE Methods

// DefaultSetup runs Setup with default inputs
func DefaultSetup() (MasterKey, PublicParams) {
	return Setup(R, Q)
}

// Setup initializaes the MSK and PP
func Setup(r int, q int) (msk MasterKey, pp PublicParams) {
	pbc.SetCryptoRandom()

	msk = MasterKey{}
	pp = PublicParams{R: r, Q: q}

	pp.Params = pbc.GenerateA(uint32(r), uint32(q))
	pp.Pairing = pp.Params.NewPairing()

	pairing := pp.Pairing

	pp.G = pairing.NewG1().Rand()
	pp.G0 = pairing.NewG1().Rand()
	pp.G1 = pairing.NewG1().Rand()

	msk.W = pairing.NewZr().Rand()
	msk.T1 = pairing.NewZr().Rand()
	msk.T2 = pairing.NewZr().Rand()
	msk.T3 = pairing.NewZr().Rand()
	msk.T4 = pairing.NewZr().Rand()

	exp := pairing.NewZr().Mul(pairing.NewZr().Mul(msk.T1, msk.T2), msk.W)
	pp.O = pairing.NewGT().PowZn(pairing.NewGT().Pair(pp.G, pp.G), exp)

	pp.V1 = pairing.NewG1().PowZn(pp.G, msk.T1)
	pp.V2 = pairing.NewG1().PowZn(pp.G, msk.T2)
	pp.V3 = pairing.NewG1().PowZn(pp.G, msk.T3)
	pp.V4 = pairing.NewG1().PowZn(pp.G, msk.T4)

	msk.Params = pp

	return
}

// Encrypt encrpyts to an id a message m
func (msk MasterKey) Extract(id string) (sk PrivateKey) {
	pbc.SetCryptoRandom()

	pp := msk.Params
	pairing := pp.Pairing

	idEl := pairing.NewZr().SetBytes(SHA2(id))

	r1, r2 := pairing.NewZr().Rand(), pairing.NewZr().Rand()

	gog1_pid := pairing.NewG1().Mul(pp.G0, pairing.NewG1().PowZn(pp.G1, idEl))

	//D0
	d01 := pairing.NewZr().Mul(pairing.NewZr().Mul(r1, msk.T1), msk.T2)
	d02 := pairing.NewZr().Mul(pairing.NewZr().Mul(r2, msk.T3), msk.T4)
	sk.D0 = pairing.NewG1().PowZn(pp.G, pairing.NewZr().Add(d01, d02))

	//D1
	nw_t2 := pairing.NewZr().Mul(pairing.NewZr().Neg(msk.W), msk.T2)
	nr1_t2 := pairing.NewZr().Mul(pairing.NewZr().Neg(r1), msk.T2)

	sk.D1 = pairing.NewG1().Mul(pairing.NewG1().PowZn(pp.G, nw_t2), pairing.NewG1().PowZn(gog1_pid, nr1_t2))

	//D2
	nw_t1 := pairing.NewZr().Mul(pairing.NewZr().Neg(msk.W), msk.T1)
	nr1_t1 := pairing.NewZr().Mul(pairing.NewZr().Neg(r1), msk.T1)
	sk.D2 = pairing.NewG1().Mul(pairing.NewG1().PowZn(pp.G, nw_t1), pairing.NewG1().PowZn(gog1_pid, nr1_t1))

	//D3
	nr2_t4 := pairing.NewZr().Mul(pairing.NewZr().Neg(r2), msk.T4)
	sk.D3 = pairing.NewG1().PowZn(gog1_pid, nr2_t4)

	//D4
	nr2_t3 := pairing.NewZr().Mul(pairing.NewZr().Neg(r2), msk.T3)
	sk.D4 = pairing.NewG1().PowZn(gog1_pid, nr2_t3)

	return sk
}

// Encrypt encrpyts to an id a message m
func (pp PublicParams) Encrypt(id string, m *pbc.Element) (ctxt CipherText) {
	pbc.SetCryptoRandom()

	pairing := pp.Pairing

	idEl := pairing.NewZr().SetBytes(SHA2(id))

	s, s1, s2 := pairing.NewZr().Rand(), pairing.NewZr().Rand(), pairing.NewZr().Rand()

	ctxt.C = pairing.NewGT().Mul(pairing.NewGT().PowZn(pp.O, s), m)
	ctxt.C0 = pairing.NewG1().PowZn(pairing.NewG1().Mul(pp.G0, pairing.NewG1().PowZn(pp.G1, idEl)), s)

	ctxt.C1 = pairing.NewG1().PowZn(pp.V1, pairing.NewZr().Sub(s, s1))
	ctxt.C2 = pairing.NewG1().PowZn(pp.V2, s1)
	ctxt.C3 = pairing.NewG1().PowZn(pp.V3, pairing.NewZr().Sub(s, s2))
	ctxt.C4 = pairing.NewG1().PowZn(pp.V4, s2)

	return ctxt
}

// Encrypt encrpyts to an id a message m
func (pp PublicParams) Decrypt(sk PrivateKey, ctxt CipherText) *pbc.Element {
	pbc.SetCryptoRandom()

	pairing := pp.Pairing

	e0 := pairing.NewGT().Pair(ctxt.C0, sk.D0)
	e1 := pairing.NewGT().Pair(ctxt.C1, sk.D1)
	e2 := pairing.NewGT().Pair(ctxt.C2, sk.D2)
	e3 := pairing.NewGT().Pair(ctxt.C3, sk.D3)
	e4 := pairing.NewGT().Pair(ctxt.C4, sk.D4)

	return pairing.NewGT().Mul(ctxt.C, pairing.NewGT().Mul(e0, pairing.NewGT().Mul(e1, pairing.NewGT().Mul(e2, pairing.NewGT().Mul(e3, e4)))))
}

//MARK: Convenience Encrypt/Decrypt

const trueEl = "true"

func (pp PublicParams) EncryptKeyword(id string) CipherText {
	m := pp.Pairing.NewGT().SetFromStringHash(trueEl, sha256.New())
	return pp.Encrypt(id, m)
}

func (pp PublicParams) DecryptAndCheck(sk PrivateKey, ctxt CipherText) bool {
	mG := pp.Decrypt(sk, ctxt)
	return pp.Pairing.NewGT().SetFromStringHash(trueEl, sha256.New()).Equals(mG)
}

//MARK: Helpers

func (pp PublicParams) ValBytes(m []byte) []byte {
	return pp.Pairing.NewGT().SetBytes(m).Bytes()
}

func SHA2(data string) []byte {
	h := sha256.New()
	h.Write([]byte(data))
	return h.Sum(nil)
}
