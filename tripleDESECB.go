package cryptoutils

import (
	"crypto/des"
	"errors"
)

type tripleDESECBEncrypt struct{}

func (tripleDESECBEncrypt) Encrypt(src, key []byte,
	p Padder) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	pSrc := p.Pad(src, block.BlockSize())
	if len(pSrc)%block.BlockSize() != 0 {
		return nil, errors.New("need a multiple of the block size")
	}
	out := make([]byte, len(pSrc))
	dst := out
	for len(pSrc) > 0 {
		block.Encrypt(dst, pSrc[:block.BlockSize()])
		pSrc = pSrc[block.BlockSize():]
		dst = dst[block.BlockSize():]
	}
	return out, nil
}

type tripleDESECBDecrypt struct{}

func (tripleDESECBDecrypt) Decrypt(src, key []byte,
	unp UnPadder) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(src))
	dst := out
	if len(out)%block.BlockSize() != 0 {
		return nil, errors.New("crypto/cipher: input not full blocks")
	}
	for len(src) > 0 {
		block.Decrypt(dst, src[:block.BlockSize()])
		src = src[block.BlockSize():]
		dst = dst[block.BlockSize():]
	}
	out, err = unp.UnPad(out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

//NewTripleDESECBEncrypter triple DES ECB encrypter
func NewTripleDESECBEncrypter() ECBEncrypter {
	return tripleDESECBEncrypt{}
}

//NewTripleDESECBDecrypter triple DES ECB decrypter
func NewTripleDESECBDecrypter() ECBDecrypter {
	return tripleDESECBDecrypt{}
}
