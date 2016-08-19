package cryptutil

import "crypto/sha256"

func H(a, b []byte) []byte {
	msg := make([]byte, 64)

	copy(msg[:32], SHA2(a))
	copy(msg[32:], SHA2(b))

	return SHA2(msg)
}

func SHA2(b []byte) []byte {
	h := sha256.New()
	h.Write(b)
	return h.Sum(nil)
}
