package cryptoutils

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
)

var (
	key []byte
)

func TestCBCEncrypt(t *testing.T) {
	encrypter := NewTripleDESCBCEncrypter()
	result, err := encrypter.Encrypt([]byte("test"), key, []byte("myivvyiv"), NewPKCS5Padding())
	if err != nil {
		t.Error(err)
	}
	if base64.StdEncoding.EncodeToString(result) != "XNBtZPI3/80=" {
		t.Errorf("expect: xdmxSIggxfGhgsLYYgQtRQ==, result: %s", result)
	}
	t.Logf("expect: XNBtZPI3/80=, result: %s", base64.StdEncoding.EncodeToString(result))
}

func TestCBCDecrypt(t *testing.T) {
	decrypter := NewTripleDESCBCDecrypter()
	src, _ := base64.StdEncoding.DecodeString("XNBtZPI3/80=")
	result, err := decrypter.Decrypt(src, key, []byte("myivvyiv"), NewPKCS5Padding())
	if err != nil {
		t.Error(err)
	}
	if string(result) != "test" {
		t.Errorf("expect: test, result: %s", result)
	}
	t.Logf("expect: test, result: %s", result)
}

func init() {
	key, _ = hex.DecodeString("9B7A577AFBD90DF8AECE13869813F1E02AE3E64558018C9E")
}
