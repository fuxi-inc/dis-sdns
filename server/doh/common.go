package doh

import "crypto/sha256"

func Hash(msg []byte) []byte {

	hash := sha256.New()
	_, err := hash.Write(msg)
	if err != nil {
		panic(err)
	}

	return hash.Sum(nil)
}
