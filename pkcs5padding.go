package cryptoutils

import (
	"bytes"
	"errors"
)

type pkcs5Padding struct {
	pkcs5Pad
	pkcs5UnPad
}

type pkcs5Pad struct{}

func (pkcs5Pad) Pad(src []byte, blockSize int) []byte {
	p := blockSize - len(src)%blockSize
	pSrc := bytes.Repeat([]byte{byte(p)}, p)
	return append(src, pSrc...)
}

type pkcs5UnPad struct{}

func (pkcs5UnPad) UnPad(src []byte) ([]byte, error) {
	length := len(src)
	unp := int(src[length-1])
	if length < unp {
		return nil, errors.New("unpadding error")
	}
	return src[:(length - unp)], nil
}

//NewPKCS5Padding PKCS5 padding
func NewPKCS5Padding() PadUnpader {
	return pkcs5Padding{}
}
