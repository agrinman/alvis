package ibe

import (
	"encoding/base64"

	"github.com/Nik-U/pbc"
)

//MARK: PublicParams
type PublicParamsSerialized struct {
	Params string

	R int
	Q int

	O  string
	G  string
	G0 string
	G1 string

	V1 string
	V2 string
	V3 string
	V4 string
}

func (pp PublicParams) ToSerialized() (ser PublicParamsSerialized) {
	ser.Params = pp.Params.String()

	ser.O = base64.URLEncoding.EncodeToString(pp.O.Bytes())
	ser.G = base64.URLEncoding.EncodeToString(pp.G.Bytes())
	ser.G0 = base64.URLEncoding.EncodeToString(pp.G0.Bytes())
	ser.G1 = base64.URLEncoding.EncodeToString(pp.G1.Bytes())

	ser.V1 = base64.URLEncoding.EncodeToString(pp.V1.Bytes())
	ser.V2 = base64.URLEncoding.EncodeToString(pp.V2.Bytes())
	ser.V3 = base64.URLEncoding.EncodeToString(pp.V3.Bytes())
	ser.V4 = base64.URLEncoding.EncodeToString(pp.V4.Bytes())

	return ser
}

func (ser PublicParamsSerialized) ToPublicParams() (pp PublicParams, err error) {
	pbc.SetCryptoRandom()

	pp.Params, err = pbc.NewParamsFromString(ser.Params)
	if err != nil {
		return
	}

	pp.Pairing, err = pbc.NewPairingFromString(ser.Params)
	if err != nil {
		return
	}

	pairing := pp.Pairing

	// G
	G, err := base64.URLEncoding.DecodeString(ser.G)
	if err != nil {
		return
	}
	pp.G = pairing.NewG1().SetBytes(G)

	// G0
	G0, err := base64.URLEncoding.DecodeString(ser.G0)
	if err != nil {
		return
	}
	pp.G0 = pairing.NewG1().SetBytes(G0)

	// G1
	G1, err := base64.URLEncoding.DecodeString(ser.G1)
	if err != nil {
		return
	}
	pp.G1 = pairing.NewG1().SetBytes(G1)

	// O
	O, err := base64.URLEncoding.DecodeString(ser.O)
	if err != nil {
		return
	}
	pp.O = pairing.NewGT().SetBytes(O)

	//V1
	V1, err := base64.URLEncoding.DecodeString(ser.V1)
	if err != nil {
		return
	}
	pp.V1 = pairing.NewG1().SetBytes(V1)

	//V2
	V2, err := base64.URLEncoding.DecodeString(ser.V2)
	if err != nil {
		return
	}
	pp.V2 = pairing.NewG1().SetBytes(V2)

	//V3
	V3, err := base64.URLEncoding.DecodeString(ser.V3)
	if err != nil {
		return
	}
	pp.V3 = pairing.NewG1().SetBytes(V3)

	//V4
	V4, err := base64.URLEncoding.DecodeString(ser.V4)
	if err != nil {
		return
	}
	pp.V4 = pairing.NewG1().SetBytes(V4)

	return
}

//MARK: Master Key
type MasterKeySerialized struct {
	Params PublicParamsSerialized
	W      string
	T1     string
	T2     string
	T3     string
	T4     string
}

func MarshalMasterKey(msk MasterKey) (ser MasterKeySerialized, err error) {
	ser = MasterKeySerialized{}

	ser.Params = msk.Params.ToSerialized()
	ser.W = base64.URLEncoding.EncodeToString(msk.W.Bytes())
	ser.T1 = base64.URLEncoding.EncodeToString(msk.T1.Bytes())
	ser.T2 = base64.URLEncoding.EncodeToString(msk.T2.Bytes())
	ser.T3 = base64.URLEncoding.EncodeToString(msk.T3.Bytes())
	ser.T4 = base64.URLEncoding.EncodeToString(msk.T4.Bytes())

	return
}

func UnmarshalMasterKey(ser MasterKeySerialized) (msk MasterKey, err error) {
	msk.Params, err = ser.Params.ToPublicParams()
	if err != nil {
		return
	}

	pairing := msk.Params.Pairing

	// W
	W, err := base64.URLEncoding.DecodeString(ser.W)
	if err != nil {
		return
	}
	msk.W = pairing.NewZr().SetBytes(W)

	//T1
	T1, err := base64.URLEncoding.DecodeString(ser.T1)
	if err != nil {
		return
	}
	msk.T1 = pairing.NewZr().SetBytes(T1)

	//T2
	T2, err := base64.URLEncoding.DecodeString(ser.T2)
	if err != nil {
		return
	}
	msk.T2 = pairing.NewZr().SetBytes(T2)

	//T3
	T3, err := base64.URLEncoding.DecodeString(ser.T3)
	if err != nil {
		return
	}
	msk.T3 = pairing.NewZr().SetBytes(T3)

	//T4
	T4, err := base64.URLEncoding.DecodeString(ser.T4)
	if err != nil {
		return
	}
	msk.T4 = pairing.NewZr().SetBytes(T4)

	return
}

//MARK: Private Key
type PrivateKeySerialized struct {
	Params  PublicParamsSerialized
	Keyword string
	D0      string
	D1      string
	D2      string
	D3      string
	D4      string
}

func MarshallPrivateKey(pp PublicParams, sk PrivateKey) (ser PrivateKeySerialized, err error) {
	ser = PrivateKeySerialized{}
	ser.Keyword = sk.Keyword
	ser.Params = pp.ToSerialized()

	ser.D0 = base64.URLEncoding.EncodeToString(sk.D0.Bytes())
	ser.D1 = base64.URLEncoding.EncodeToString(sk.D1.Bytes())
	ser.D2 = base64.URLEncoding.EncodeToString(sk.D2.Bytes())
	ser.D3 = base64.URLEncoding.EncodeToString(sk.D3.Bytes())
	ser.D4 = base64.URLEncoding.EncodeToString(sk.D4.Bytes())

	return
}

func UnmarshalPrivateKey(params PublicParams, ser PrivateKeySerialized) (sk PrivateKey, err error) {
	pairing := params.Pairing

	sk.Keyword = ser.Keyword

	// W
	D0, err := base64.URLEncoding.DecodeString(ser.D0)
	if err != nil {
		return
	}
	sk.D0 = pairing.NewG1().SetBytes(D0)

	//D1
	D1, err := base64.URLEncoding.DecodeString(ser.D1)
	if err != nil {
		return
	}
	sk.D1 = pairing.NewG1().SetBytes(D1)

	//D2
	D2, err := base64.URLEncoding.DecodeString(ser.D2)
	if err != nil {
		return
	}
	sk.D2 = pairing.NewG1().SetBytes(D2)

	//D3
	D3, err := base64.URLEncoding.DecodeString(ser.D3)
	if err != nil {
		return
	}
	sk.D3 = pairing.NewG1().SetBytes(D3)

	//D4
	D4, err := base64.URLEncoding.DecodeString(ser.D4)
	if err != nil {
		return
	}
	sk.D4 = pairing.NewG1().SetBytes(D4)

	return
}

//MARK: CipherText
type CipherTextSerialized struct {
	C  string
	C0 string
	C1 string
	C2 string
	C3 string
	C4 string
}

func MarshallCipherText(pp PublicParams, ctxt CipherText) (ser CipherTextSerialized, err error) {
	ser = CipherTextSerialized{}

	ser.C = base64.URLEncoding.EncodeToString(ctxt.C.Bytes())
	ser.C0 = base64.URLEncoding.EncodeToString(ctxt.C0.Bytes())
	ser.C1 = base64.URLEncoding.EncodeToString(ctxt.C1.Bytes())
	ser.C2 = base64.URLEncoding.EncodeToString(ctxt.C2.Bytes())
	ser.C3 = base64.URLEncoding.EncodeToString(ctxt.C3.Bytes())
	ser.C4 = base64.URLEncoding.EncodeToString(ctxt.C4.Bytes())

	return
}

func UnmarshalCipherText(params PublicParams, ser CipherTextSerialized) (ctxt CipherText, err error) {
	pairing := params.Pairing

	// C
	C, err := base64.URLEncoding.DecodeString(ser.C)
	if err != nil {
		return
	}
	ctxt.C = pairing.NewGT().SetBytes(C)

	// C0
	C0, err := base64.URLEncoding.DecodeString(ser.C0)
	if err != nil {
		return
	}
	ctxt.C0 = pairing.NewG1().SetBytes(C0)

	//C1
	C1, err := base64.URLEncoding.DecodeString(ser.C1)
	if err != nil {
		return
	}
	ctxt.C1 = pairing.NewG1().SetBytes(C1)

	//C2
	C2, err := base64.URLEncoding.DecodeString(ser.C2)
	if err != nil {
		return
	}
	ctxt.C2 = pairing.NewG1().SetBytes(C2)

	//C3
	C3, err := base64.URLEncoding.DecodeString(ser.C3)
	if err != nil {
		return
	}
	ctxt.C3 = pairing.NewG1().SetBytes(C3)

	//C4
	C4, err := base64.URLEncoding.DecodeString(ser.C4)
	if err != nil {
		return
	}
	ctxt.C4 = pairing.NewG1().SetBytes(C4)

	return
}

func MarshalCipherTextBase64(ctxt CipherText) (result string, err error) {

	bytesLen := ctxt.C.BytesLen() + ctxt.C0.BytesLen() + ctxt.C1.BytesLen() + ctxt.C2.BytesLen() + ctxt.C3.BytesLen() + ctxt.C4.BytesLen()

	ctxtBytes := make([]byte, bytesLen)

	count := 0
	copy(ctxtBytes[count:count+ctxt.C.BytesLen()], ctxt.C.Bytes())
	count += ctxt.C.BytesLen()

	copy(ctxtBytes[count:count+ctxt.C0.BytesLen()], ctxt.C0.Bytes())
	count += ctxt.C0.BytesLen()

	copy(ctxtBytes[count:count+ctxt.C1.BytesLen()], ctxt.C1.Bytes())
	count += ctxt.C1.BytesLen()

	copy(ctxtBytes[count:count+ctxt.C2.BytesLen()], ctxt.C2.Bytes())
	count += ctxt.C2.BytesLen()

	copy(ctxtBytes[count:count+ctxt.C3.BytesLen()], ctxt.C3.Bytes())
	count += ctxt.C3.BytesLen()

	copy(ctxtBytes[count:count+ctxt.C2.BytesLen()], ctxt.C4.Bytes())
	count += ctxt.C4.BytesLen()

	result = base64.URLEncoding.EncodeToString(ctxtBytes)

	return
}

func UnmarshalCipherTextBase64(params PublicParams, ctxtString string) (ctxt CipherText, err error) {

	ctxtBytes, err := base64.URLEncoding.DecodeString(ctxtString)
	if err != nil {
		return
	}

	blockSize := 128
	count := 0

	pairing := params.Pairing

	// C
	ctxt.C = pairing.NewGT().SetBytes(ctxtBytes[count : count+blockSize])
	count += blockSize

	// C0
	ctxt.C0 = pairing.NewG1().SetBytes(ctxtBytes[count : count+blockSize])
	count += blockSize

	//C1
	ctxt.C1 = pairing.NewG1().SetBytes(ctxtBytes[count : count+blockSize])
	count += blockSize

	//C2
	ctxt.C2 = pairing.NewG1().SetBytes(ctxtBytes[count : count+blockSize])
	count += blockSize

	//C3
	ctxt.C3 = pairing.NewG1().SetBytes(ctxtBytes[count : count+blockSize])
	count += blockSize

	//C4
	ctxt.C4 = pairing.NewG1().SetBytes(ctxtBytes[count : count+blockSize])

	return
}

//MARK: Unique
func (sk PrivateKeySerialized) Unique() string {
	return sk.D0 + sk.D1 + sk.D2 + sk.D3 + sk.D4
}

func (ctxt CipherTextSerialized) Unique() string {
	return ctxt.C + ctxt.C0 + ctxt.C1 + ctxt.C2 + ctxt.C3 + ctxt.C4
}
