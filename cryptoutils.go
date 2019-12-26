package cryptoutils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
)

type Pader interface {
	Pad(src []byte, blockSize int) []byte
	UnPad(src []byte) ([]byte, error)
}

type Cypher struct {
	Block cipher.Block
	Error error
}

func (c Cypher) NewCBC(IV []byte, Padding Pader) CBC {
	return CBC{Cypher: c, IV: IV, Padding: Padding}
}

type CBC struct {
	Cypher
	IV      []byte
	Padding Pader
}

func (c CBC) Encrypt(data []byte) Result {
	pData := c.Padding.Pad(data, c.Cypher.Block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(c.Cypher.Block, c.IV)
	out := make([]byte, len(pData))
	blockMode.CryptBlocks(out, pData)
	return Result{Data: out, Error: nil}
}

func (c CBC) Decrypt(data []byte) Result {
	cipher.NewCBCDecrypter(c.Cypher.Block, c.IV).CryptBlocks(data, data)
	out, err := c.Padding.UnPad(data)
	if err != nil {
		return Result{Data: nil, Error: err}
	}
	return Result{Data: out, Error: err}
}

type Result struct {
	Data  []byte
	Error error
}

func NewAES(key []byte) Cypher {
	b, err := aes.NewCipher(key)
	return Cypher{Block: b, Error: err}
}

func NewTripleDES(key []byte) Cypher {
	b, err := des.NewCipher(key)
	return Cypher{Block: b, Error: err}
}
