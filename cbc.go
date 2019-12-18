package cryptoutils

//CBCEncrypter interface
type CBCEncrypter interface {
	Encrypt(src, key, iv []byte, p Padder) ([]byte, error)
}

//CBCDecrypter interface
type CBCDecrypter interface {
	Decrypt(src, key, iv []byte, unp UnPadder) ([]byte, error)
}

//CBCEncryptDecrypter interface
type CBCEncryptDecrypter interface {
	CBCEncrypter
	CBCDecrypter
}
