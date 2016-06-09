package freqFE

import "github.com/agrinman/alvis/aesutil"

const KeySize = 256

type MasterKey struct {
	InnerKey []byte
	IV       []byte
	OuterKey []byte
}

func GenMasterKey() (master MasterKey, err error) {
	innerKey, err := aesutil.RandKey()
	if err != nil {
		return
	}

	innerIV, err := aesutil.RandIV()
	if err != nil {
		return
	}

	outer, err := aesutil.RandKey()
	if err != nil {
		return
	}

	return MasterKey{innerKey, innerIV, outer}, err
}

func EncryptInnerOuter(master MasterKey, message []byte) (result []byte, err error) {
	innerEnc, err := aesutil.AESEncryptWithIV(master.InnerKey, master.IV, message)
	if err != nil {
		return
	}

	result, err = aesutil.AESEncrypt(master.OuterKey, innerEnc)
	return
}

func DecryptOuterInner(master MasterKey, cipherText []byte) (result []byte, err error) {
	outerDec, err := aesutil.AESDecrypt(master.OuterKey, cipherText)
	if err != nil {
		return
	}

	result, err = aesutil.AESDecryptWithIV(master.InnerKey, master.IV, outerDec)
	return
}

func DecryptOuter(outer []byte, cipherText []byte) (result []byte, err error) {
	result, err = aesutil.AESDecrypt(outer, cipherText)
	return
}

func DecryptInner(master MasterKey, cipherText []byte) (result []byte, err error) {
	result, err = aesutil.AESDecryptWithIV(master.InnerKey, master.IV, cipherText)
	return
}
