package cryptoutils

//Padder interface
type Padder interface {
	Pad(src []byte, blockSize int) []byte
}

//UnPadder interface
type UnPadder interface {
	UnPad(src []byte) ([]byte, error)
}

//PadUnpader interface
type PadUnpader interface {
	Padder
	UnPadder
}
