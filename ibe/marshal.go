package ibe

import (
	"encoding/base64"
	"encoding/json"

	"github.com/Nik-U/pbc"
)

//MARK: PublicParams
type PublicParamsSerialized struct {
	Params string

	R uint32
	Q uint32

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

	ser.R = pp.R
	ser.Q = pp.Q

	ser.O = base64.StdEncoding.EncodeToString(pp.O.Bytes())
	ser.G = base64.StdEncoding.EncodeToString(pp.G.Bytes())
	ser.G0 = base64.StdEncoding.EncodeToString(pp.G0.Bytes())
	ser.G1 = base64.StdEncoding.EncodeToString(pp.G1.Bytes())

	ser.V1 = base64.StdEncoding.EncodeToString(pp.V1.Bytes())
	ser.V2 = base64.StdEncoding.EncodeToString(pp.V2.Bytes())
	ser.V3 = base64.StdEncoding.EncodeToString(pp.V3.Bytes())
	ser.V4 = base64.StdEncoding.EncodeToString(pp.V4.Bytes())

	return
}

func (ser PublicParamsSerialized) ToPublicParams() (pp PublicParams, err error) {
	pp.Params, err = pbc.NewParamsFromString(ser.Params)
	if err != nil {
		return
	}

	pp.Pairing = pp.Params.NewPairing()
	pairing := pp.Pairing

	// G
	G, err := base64.StdEncoding.DecodeString(ser.G)
	if err != nil {
		return
	}
	pp.G = pairing.NewG1().SetBytes(G)

	// G0
	G0, err := base64.StdEncoding.DecodeString(ser.G0)
	if err != nil {
		return
	}
	pp.G0 = pairing.NewG1().SetBytes(G0)

	// G1
	G1, err := base64.StdEncoding.DecodeString(ser.G1)
	if err != nil {
		return
	}
	pp.G1 = pairing.NewG1().SetBytes(G1)

	// O
	O, err := base64.StdEncoding.DecodeString(ser.O)
	if err != nil {
		return
	}
	pp.O = pairing.NewGT().SetBytes(O)

	//V1
	V1, err := base64.StdEncoding.DecodeString(ser.V1)
	if err != nil {
		return
	}
	pp.V1 = pairing.NewG1().SetBytes(V1)

	//V2
	V2, err := base64.StdEncoding.DecodeString(ser.V2)
	if err != nil {
		return
	}
	pp.V2 = pairing.NewG1().SetBytes(V2)

	//V3
	V3, err := base64.StdEncoding.DecodeString(ser.V3)
	if err != nil {
		return
	}
	pp.V3 = pairing.NewG1().SetBytes(V3)

	//V4
	V4, err := base64.StdEncoding.DecodeString(ser.V4)
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

func MarshalMasterKey(msk MasterKey) (result []byte, err error) {
	ser := MasterKeySerialized{}

	ser.Params = msk.Params.ToSerialized()
	ser.W = base64.StdEncoding.EncodeToString(msk.W.Bytes())
	ser.T1 = base64.StdEncoding.EncodeToString(msk.T1.Bytes())
	ser.T2 = base64.StdEncoding.EncodeToString(msk.T2.Bytes())
	ser.T3 = base64.StdEncoding.EncodeToString(msk.T3.Bytes())
	ser.T4 = base64.StdEncoding.EncodeToString(msk.T4.Bytes())

	result, err = json.MarshalIndent(&ser, " ", "    ")
	return
}

func UnmarshalMasterKey(data []byte) (msk MasterKey, err error) {
	var ser MasterKeySerialized
	err = json.Unmarshal(data, &ser)
	if err != nil {
		return
	}

	msk.Params, err = ser.Params.ToPublicParams()
	if err != nil {
		return
	}

	pairing := msk.Params.Pairing

	// W
	W, err := base64.StdEncoding.DecodeString(ser.W)
	if err != nil {
		return
	}
	msk.W = pairing.NewZr().SetBytes(W)

	//T1
	T1, err := base64.StdEncoding.DecodeString(ser.T1)
	if err != nil {
		return
	}
	msk.T1 = pairing.NewZr().SetBytes(T1)

	//T2
	T2, err := base64.StdEncoding.DecodeString(ser.T2)
	if err != nil {
		return
	}
	msk.T2 = pairing.NewZr().SetBytes(T2)

	//T3
	T3, err := base64.StdEncoding.DecodeString(ser.T3)
	if err != nil {
		return
	}
	msk.T3 = pairing.NewZr().SetBytes(T3)

	//T4
	T4, err := base64.StdEncoding.DecodeString(ser.T4)
	if err != nil {
		return
	}
	msk.T4 = pairing.NewZr().SetBytes(T4)

	return
}

//MARK: Private Key
type PrivateKeySerialized struct {
	Params PublicParamsSerialized
	D0     string
	D1     string
	D2     string
	D3     string
	D4     string
}

func MarshallPrivateKey(pp PublicParams, sk PrivateKey) (result []byte, err error) {
	ser := PrivateKeySerialized{}

	ser.Params = pp.ToSerialized()
	ser.D0 = base64.StdEncoding.EncodeToString(sk.D0.Bytes())
	ser.D1 = base64.StdEncoding.EncodeToString(sk.D1.Bytes())
	ser.D2 = base64.StdEncoding.EncodeToString(sk.D2.Bytes())
	ser.D3 = base64.StdEncoding.EncodeToString(sk.D3.Bytes())
	ser.D4 = base64.StdEncoding.EncodeToString(sk.D4.Bytes())

	result, err = json.MarshalIndent(&ser, " ", "    ")
	return
}

func UnmarshalPrivateKey(data []byte) (sk PrivateKey, params PublicParams, err error) {
	var ser PrivateKeySerialized
	err = json.Unmarshal(data, &ser)
	if err != nil {
		return
	}

	params, err = ser.Params.ToPublicParams()
	if err != nil {
		return
	}

	pairing := params.Pairing

	// W
	D0, err := base64.StdEncoding.DecodeString(ser.D0)
	if err != nil {
		return
	}
	sk.D0 = pairing.NewG1().SetBytes(D0)

	//D1
	D1, err := base64.StdEncoding.DecodeString(ser.D1)
	if err != nil {
		return
	}
	sk.D1 = pairing.NewG1().SetBytes(D1)

	//D2
	D2, err := base64.StdEncoding.DecodeString(ser.D2)
	if err != nil {
		return
	}
	sk.D2 = pairing.NewG1().SetBytes(D2)

	//D3
	D3, err := base64.StdEncoding.DecodeString(ser.D3)
	if err != nil {
		return
	}
	sk.D3 = pairing.NewG1().SetBytes(D3)

	//D4
	D4, err := base64.StdEncoding.DecodeString(ser.D4)
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

func MarshallCipherText(pp PublicParams, ctxt CipherText) (result []byte, err error) {
	ser := CipherTextSerialized{}

	ser.C = base64.StdEncoding.EncodeToString(ctxt.C.Bytes())
	ser.C0 = base64.StdEncoding.EncodeToString(ctxt.C0.Bytes())
	ser.C1 = base64.StdEncoding.EncodeToString(ctxt.C1.Bytes())
	ser.C2 = base64.StdEncoding.EncodeToString(ctxt.C2.Bytes())
	ser.C3 = base64.StdEncoding.EncodeToString(ctxt.C3.Bytes())
	ser.C4 = base64.StdEncoding.EncodeToString(ctxt.C4.Bytes())

	result, err = json.MarshalIndent(&ser, " ", "    ")
	return
}

func UnmarshalCipherText(params PublicParams, data []byte) (ctxt CipherText, err error) {
	var ser CipherTextSerialized
	err = json.Unmarshal(data, &ser)
	if err != nil {
		return
	}

	pairing := params.Pairing

	// C
	C, err := base64.StdEncoding.DecodeString(ser.C)
	if err != nil {
		return
	}
	ctxt.C = pairing.NewGT().SetBytes(C)

	// C0
	C0, err := base64.StdEncoding.DecodeString(ser.C0)
	if err != nil {
		return
	}
	ctxt.C0 = pairing.NewG1().SetBytes(C0)

	//C1
	C1, err := base64.StdEncoding.DecodeString(ser.C1)
	if err != nil {
		return
	}
	ctxt.C1 = pairing.NewG1().SetBytes(C1)

	//C2
	C2, err := base64.StdEncoding.DecodeString(ser.C2)
	if err != nil {
		return
	}
	ctxt.C2 = pairing.NewG1().SetBytes(C2)

	//C3
	C3, err := base64.StdEncoding.DecodeString(ser.C3)
	if err != nil {
		return
	}
	ctxt.C3 = pairing.NewG1().SetBytes(C3)

	//C4
	C4, err := base64.StdEncoding.DecodeString(ser.C4)
	if err != nil {
		return
	}
	ctxt.C4 = pairing.NewG1().SetBytes(C4)

	return
}
