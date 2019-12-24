package cryptoutils

import (
	"crypto/aes"
	"crypto/cipher"
)

type Pader interface {
	Pad(src []byte, blockSize int) []byte
	UnPad(src []byte) ([]byte, error)
}

type AESCBCEncrypt struct{}

func (AESCBCEncrypt) Encrypt(src, key, iv []byte,
	p Pader) ([]byte, error) {
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

type AESCBCDecrypt struct{}

func (AESCBCDecrypt) Decrypt(src, key, iv []byte,
	unp Pader) ([]byte, error) {
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
func NewAESCBCEncrypt() AESCBCEncrypt {
	return AESCBCEncrypt{}
}

//NewAESCBCDecrypt decrypts AES
func NewAESCBCDecrypt() AESCBCDecrypt {
	return AESCBCDecrypt{}
}
