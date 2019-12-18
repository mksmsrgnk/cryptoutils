package cryptoutils

//ECBEncrypter interface
type ECBEncrypter interface {
	Encrypt(src, key []byte, p Padder) ([]byte, error)
}

//ECBDecrypter interface
type ECBDecrypter interface {
	Decrypt(src, key []byte, unp UnPadder) ([]byte, error)
}

//ECBEncryptDecrypter interface
type ECBEncryptDecrypter interface {
	ECBEncrypter
	ECBDecrypter
}
