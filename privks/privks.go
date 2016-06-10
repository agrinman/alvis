package privKS

import (
	"crypto/sha256"

	"github.com/agrinman/alvis/aesutil"
)

type MasterKey struct {
	Salt []byte
}

type PrivateKey struct {
	Keyword string
	Key     []byte
}

var OneVec = []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

//MARK: Private Encryption Keyword Search Methods

func GenMasterKey() (msk MasterKey, err error) {
	msk.Salt, err = aesutil.RandKey()
	return
}

// Encrypt encrpyts to an id a message m
func (msk MasterKey) Extract(id string) (sk PrivateKey) {
	return PrivateKey{id, h(id, msk.Salt)}
}

func (msk MasterKey) EncryptKeyword(id string) (res []byte, err error) {
	sk := msk.Extract(id)
	res, err = aesutil.AESEncrypt(sk.Key, OneVec)

	return
}

func (sk PrivateKey) DecryptAndCheck(ctx []byte) bool {
	res, err := aesutil.AESDecrypt(sk.Key, ctx)
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

//MARK: Hash

func h(id string, salt []byte) []byte {
	msg := make([]byte, 64)

	copy(msg[:32], SHA2([]byte(id)))
	copy(msg[32:], SHA2(salt))

	return SHA2(msg)
}

func SHA2(b []byte) []byte {
	h := sha256.New()
	h.Write(b)
	return h.Sum(nil)
}
