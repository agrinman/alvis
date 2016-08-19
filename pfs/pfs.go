package pfs

import "github.com/agrinman/alvis/cryptutil"

const KeySize = 256

type MasterKey struct {
	InnerKey    []byte
	OuterKey    []byte
	DetachedKey []byte
}

type Ciphertext struct {
	Detached []byte
	Hidden   []byte
}

func Setup() (master MasterKey, err error) {
	inner, err := cryptutil.RandKey()
	if err != nil {
		return
	}
	outer, err := cryptutil.RandKey()
	if err != nil {
		return
	}
	detached, err := cryptutil.RandKey()
	if err != nil {
		return
	}

	return MasterKey{inner, outer, detached}, err
}

func Disguise(master MasterKey, message []byte) (result Ciphertext, err error) {
	result.Detached, err = cryptutil.AESEncrypt(master.DetachedKey, message)
	if err != nil {
		return
	}

	result.Hidden, err = cryptutil.AESEncrypt(master.OuterKey, cryptutil.H(message, master.InnerKey))
	if err != nil {
		return
	}

	return
}

func Recognize(outer []byte, hidden []byte) (result []byte, err error) {
	result, err = cryptutil.AESDecrypt(outer, hidden)
	return
}

func RecognizeCiphertext(outer []byte, ciphertext Ciphertext) (result []byte, err error) {
	return Recognize(outer, ciphertext.Hidden)
}

func Uncover(master MasterKey, detached []byte) (result []byte, err error) {
	result, err = cryptutil.AESDecrypt(master.DetachedKey, detached)
	return
}

func UncoverCiphertext(master MasterKey, ciphertext Ciphertext) (result []byte, err error) {
	result, err = Uncover(master, ciphertext.Detached)
	return
}
