package cryptoutils

import (
	"encoding/base64"
	"github.com/mksmsrgnk/padding"
	"testing"
)

func TestAesCBCEncrypt(t *testing.T) {
	encrypter := NewAESCBCEncrypt()
	result, err := encrypter.Encrypt([]byte("test"),
		key,
		[]byte("myivmyivmyivmyiv"),
		padding.NewPKCS5())
	if err != nil {
		t.Error(err)
	}
	if base64.StdEncoding.EncodeToString(result) != "Fenn4u0yKIBiy7usB9/OpA==" {
		t.Errorf("expect: , got: %s", result)
	}
	t.Logf("expect: Fenn4u0yKIBiy7usB9/OpA==, result: %s", base64.StdEncoding.EncodeToString(result))
}

func TestAesCBCDecrypt(t *testing.T) {
	decrypter := NewAESCBCDecrypt()
	str, _ := base64.StdEncoding.DecodeString("Fenn4u0yKIBiy7usB9/OpA==")
	result, err := decrypter.Decrypt(str,
		key,
		[]byte("myivmyivmyivmyiv"),
		padding.NewPKCS5())
	if err != nil {
		t.Error(err)
	}
	if string(result) != "test" {
		t.Errorf("expect: test, got: %s", result)
	}
	t.Logf("expect: test, result: %s", result)
}
