package pks

import "github.com/agrinman/alvis/cryptutil"

type MasterKey struct {
	Salt []byte
}

type PrivateKey struct {
	Keyword string
	Key     []byte
}

var OneVec = []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

//MARK: Private Encryption Keyword Search Methods

func Setup() (msk MasterKey, err error) {
	msk.Salt, err = cryptutil.RandKey()
	return
}

// Encrypt encrpyts to an id a message m
func (msk MasterKey) Extract(id string) (sk PrivateKey) {
	return PrivateKey{id, cryptutil.H([]byte(id), msk.Salt)}
}

func (msk MasterKey) Hide(id string) (res []byte, err error) {
	sk := msk.Extract(id)
	res, err = cryptutil.AESEncrypt(sk.Key, OneVec)

	return
}

func (sk PrivateKey) Check(ctx []byte) bool {
	res, err := cryptutil.AESDecrypt(sk.Key, ctx)
	if err != nil {
		return false
	}

	if len(res) != len(OneVec) {
		return false
	}

	for i, b := range res {
		if b != OneVec[i] {
			return false
		}
	}

	return true
}
