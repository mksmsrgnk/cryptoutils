package cryptoutils

import (
	"crypto/aes"
	"crypto/cipher"
)

type aesCBCEncrypt struct{}

func (aesCBCEncrypt) Encrypt(src, key, iv []byte,
	p Padder) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	pSrc := p.Pad(src, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, iv)
	out := make([]byte, len(pSrc))
	blockMode.CryptBlocks(out, pSrc)
	return out, nil
}

type aesCBCDecrypt struct{}

func (aesCBCDecrypt) Decrypt(src, key, iv []byte,
	unp UnPadder) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, iv)
	blockMode.CryptBlocks(src, src)
	out, err := unp.UnPad(src)
	if err != nil {
		return nil, err
	}
	return out, nil
}

//NewAESCBCEncrypt encrypts AES
func NewAESCBCEncrypt() CBCEncrypter {
	return aesCBCEncrypt{}
}

//NewAESCBCDecrypt decrypts AES
func NewAESCBCDecrypt() CBCDecrypter {
	return aesCBCDecrypt{}
}
