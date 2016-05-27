package main

const KeySize = 256

type InnerKey struct {
	Key []byte
	IV  []byte
}

func GenFrequencyFE() (inner InnerKey, outer []byte, err error) {
	innerKey, err := RandKey()
	if err != nil {
		return
	}

	innerIV, err := RandIV()
	if err != nil {
		return
	}

	inner = InnerKey{innerKey, innerIV}

	outer, err = RandKey()
	if err != nil {
		return
	}

	return
}

func EncryptInnerOuter(inner InnerKey, outer []byte, message []byte) (result []byte, err error) {
	innerEnc, err := AESEncryptWithIV(inner.Key, inner.IV, message)
	if err != nil {
		return
	}

	result, err = AESEncrypt(outer, innerEnc)
	return
}

func DecryptOuterInner(inner InnerKey, outer []byte, cipherText []byte) (result []byte, err error) {
	outerDec, err := AESDecrypt(outer, cipherText)
	if err != nil {
		return
	}

	result, err = AESDecryptWithIV(inner.Key, inner.IV, outerDec)
	return
}

func DecryptOuter(outer []byte, cipherText []byte) (result []byte, err error) {
	result, err = AESDecrypt(outer, cipherText)
	return
}

func DecryptInner(inner InnerKey, cipherText []byte) (result []byte, err error) {
	result, err = AESDecryptWithIV(inner.Key, inner.IV, cipherText)
	return
}
