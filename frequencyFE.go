package main

const KeySize = 256

type FreqFEMasterKey struct {
	InnerKey []byte
	IV       []byte
	OuterKey []byte
}

func GenFrequencyFE() (master FreqFEMasterKey, err error) {
	innerKey, err := RandKey()
	if err != nil {
		return
	}

	innerIV, err := RandIV()
	if err != nil {
		return
	}

	outer, err := RandKey()
	if err != nil {
		return
	}

	return FreqFEMasterKey{innerKey, innerIV, outer}, err
}

func EncryptInnerOuter(master FreqFEMasterKey, message []byte) (result []byte, err error) {
	innerEnc, err := AESEncryptWithIV(master.InnerKey, master.IV, message)
	if err != nil {
		return
	}

	result, err = AESEncrypt(master.OuterKey, innerEnc)
	return
}

func DecryptOuterInner(master FreqFEMasterKey, cipherText []byte) (result []byte, err error) {
	outerDec, err := AESDecrypt(master.OuterKey, cipherText)
	if err != nil {
		return
	}

	result, err = AESDecryptWithIV(master.InnerKey, master.IV, outerDec)
	return
}

func DecryptOuter(outer []byte, cipherText []byte) (result []byte, err error) {
	result, err = AESDecrypt(outer, cipherText)
	return
}

func DecryptInner(master FreqFEMasterKey, cipherText []byte) (result []byte, err error) {
	result, err = AESDecryptWithIV(master.InnerKey, master.IV, cipherText)
	return
}
