package base36

import (
	"errors"
	"math/big"
)

func Encode(data []byte) (res string, err error) {
	data = append([]byte{0x01}, data...)
	n := new(big.Int).SetBytes(data)
	res = n.Text(36)
	return
}

func EncodeString(s string) (string, error) {
	return Encode([]byte(s))
}

func Decode(data []byte) ([]byte, error) {
	return DecodeString(string(data))
}

func DecodeString(str string) (data []byte, err error) {
	n, ok := new(big.Int).SetString(str, 36)
	if !ok {
		err = errors.New("Could not decode base36 string")
		return
	}

	data = n.Bytes()
	if len(data) < 1 {
		err = errors.New("Invalid byte length")
		return
	}

	data = data[1:]
	return
}
