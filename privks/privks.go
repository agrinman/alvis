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
	return
}

func (sk PrivateKey) DecryptAndCheck(ctx []byte) bool {
	return false
}

//MARK: Hash

func h(id string, salt []byte) []byte {
	msg := make([]byte, 64)

	copy(msg[:32], SHA2([]byte(id)))
	copy(msg[32:], SHA2(salt))

	return msg
}

func SHA2(b []byte) []byte {
	h := sha256.New()
	h.Write(b)
	return h.Sum(nil)
}
