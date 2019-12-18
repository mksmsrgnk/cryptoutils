package cryptoutils

import (
	"crypto/cipher"
	"crypto/des"
)

type tripleDESCBCEncrypt struct{}

func (tripleDESCBCEncrypt) Encrypt(src, key, iv []byte,
	p Padder) ([]byte, error) {
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

type tripleDESCBCDecrypt struct{}

func (tripleDESCBCDecrypt) Decrypt(src, key, iv []byte,
	unp UnPadder) ([]byte, error) {
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
func NewTripleDESCBCEncrypter() CBCEncrypter {
	return tripleDESCBCEncrypt{}
}

//NewTripleDESCBCDecrypter triple DES CBC decrypter
func NewTripleDESCBCDecrypter() CBCDecrypter {
	return tripleDESCBCDecrypt{}
}
