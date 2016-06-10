package aesutil

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
)

var KeySize = 256

//MARK: AES Wrappers
func AESEncrypt(key []byte, message []byte) (result []byte, err error) {
	// Generate Random IV
	iv, err := RandIV()
	if err != nil {
		return
	}

	encryptedMessage, err := AESEncryptWithIV(key, iv, message)

	// Pack it all together |iv|enc_pub(key)|enc_key(data)|
	result = make([]byte, len(iv)+len(encryptedMessage))
	copy(result[0:len(iv)], iv)
	copy(result[len(iv):], encryptedMessage)

	return
}

func AESEncryptWithIV(key []byte, iv []byte, message []byte) (result []byte, err error) {
	// Encrypt the message with the symmetric AES key
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	paddedMessage := PKCS7Padding([]byte(message))

	result = make([]byte, len(paddedMessage))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(result, paddedMessage)

	return
}

func AESDecrypt(key []byte, cipherText []byte) (result []byte, err error) {
	// Extract the IV, first aes block
	if len(cipherText) < aes.BlockSize {
		err = errors.New("CipherText shorter than IV")
		return
	}
	iv := cipherText[:aes.BlockSize]
	encryptedMessage := cipherText[aes.BlockSize:]

	return AESDecryptWithIV(key, iv, encryptedMessage)
}

func AESDecryptWithIV(key []byte, iv []byte, cipherText []byte) (result []byte, err error) {
	if len(cipherText) < aes.BlockSize {
		err = errors.New("CipherText shorter than block size")
		return
	}

	// Decrypt the Data with the aes key, and iv
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	result = make([]byte, len(cipherText))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(result, cipherText)
	result = UnPKCS7Padding(result)

	return
}

//MARK: Randomness Gen
func RandIV() (iv []byte, err error) {
	iv = make([]byte, aes.BlockSize)
	_, err = rand.Read(iv)
	if err != nil {
		log.Println("Could not generate IV")
		return
	}
	return
}

func RandKey() (b []byte, err error) {
	b = make([]byte, KeySize/8)
	_, err = rand.Read(b)
	if err != nil {
		fmt.Println("rand error:", err)
		return
	}
	return
}

//MARK: PKCS7 Padding
func PKCS7Padding(data []byte) []byte {
	blockSize := 16
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)

}

func UnPKCS7Padding(data []byte) []byte {
	length := len(data)
	unpadding := int(data[length-1])

	fmt.Println("length: ", length)
	fmt.Println("up: ", unpadding)
	fmt.Println("l - up: ", length-unpadding)
	fmt.Println("data: ", string(data))

	return data[:(length - unpadding)]
}

//MARK: SHA Helpers
func SHA2(data string) []byte {
	h := sha256.New()
	h.Write([]byte(data))
	return h.Sum(nil)
}
