package cryptoutils

import (
	"crypto/cipher"
	"crypto/des"
)

type TripleDESCBCEncrypt struct{}

func (TripleDESCBCEncrypt) Encrypt(src, key, iv []byte,
	p Pader) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	paddedSrc := p.Pad(src, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, iv)
	out := make([]byte, len(paddedSrc))
	blockMode.CryptBlocks(out, paddedSrc)
	return out, nil
}

type TripleDESCBCDecrypt struct{}

func (TripleDESCBCDecrypt) Decrypt(src, key, iv []byte,
	unp Pader) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, iv)
	blockMode.CryptBlocks(src, src)
	src, err = unp.UnPad(src)
	if err != nil {
		return nil, err
	}
	return src, nil
}

//NewTripleDESCBCEncrypter triple DES CBC encrypter
func NewTripleDESCBCEncrypter() TripleDESCBCEncrypt {
	return TripleDESCBCEncrypt{}
}

//NewTripleDESCBCDecrypter triple DES CBC decrypter
func NewTripleDESCBCDecrypter() TripleDESCBCDecrypt {
	return TripleDESCBCDecrypt{}
}
