package cryptutil

import "testing"

var longWord = "supercalifragilisticexpialidocious"

func BenchmarkRandKey(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			RandKey()
		}
	})
}

func BenchmarkAESEncrypt(b *testing.B) {
	k, _ := RandKey()
	msg := []byte(longWord)
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			AESEncrypt(k, msg)
		}
	})
}

func BenchmarkAESDecrypt(b *testing.B) {
	k, _ := RandKey()
	msg := []byte(longWord)
	c, _ := AESEncrypt(k, msg)

	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			AESDecrypt(k, c)
		}
	})
}

func BenchmarkHashAB(b *testing.B) {
	msg := []byte(longWord)
	k, _ := RandKey()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			H(msg, k)
		}
	})
}
