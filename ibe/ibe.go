package ibe

import "github.com/Nik-U/pbc"

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
}

type PublicParams struct {
	Params  *pbc.Params
	R, Q    uint32
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
}

//MARK: IBE Methods

// DefaultSetup runs Setup with default inputs
func DefaultSetup() (MasterKey, PublicParams, error) {
	return Setup(R, Q)
}

// Setup initializaes the MSK and PP
func Setup(r uint32, q uint32) (msk MasterKey, pp PublicParams, err error) {
	pbc.SetCryptoRandom()

	msk = MasterKey{}
	pp = PublicParams{R: r, Q: q}

	pp.Params = pbc.GenerateA(r, q)
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

	return
}

// Encrypt encrpyts to an id a message m
func (pp PublicParams) Encrypt(id string, m []byte) {
	pbc.SetCryptoRandom()

	return
}
