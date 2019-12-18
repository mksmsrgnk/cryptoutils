package cryptoutils

import "bytes"

type zeroPadding struct {
	zeroPad
	zeroUnPad
}

type zeroPad struct{}

func (zeroPad) Pad(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	paddedSrc := bytes.Repeat([]byte{0}, padding)
	return append(src, paddedSrc...)
}

type zeroUnPad struct{}

func (zeroUnPad) UnPad(src []byte) ([]byte, error) {
	return bytes.TrimFunc(src,
		func(r rune) bool {
			return r == rune(0)
		}), nil
}

//NewZerroPadding Zerro padding
func NewZerroPadding() PadUnpader {
	return zeroPadding{}
}
