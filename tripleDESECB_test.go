package cryptoutils

import (
	"encoding/base64"
	"testing"
)

func TestECBEncrypt(t *testing.T) {
	encrypter := NewTripleDESECBEncrypter()
	result, err := encrypter.Encrypt([]byte("test"), key, NewPKCS5Padding())
	if err != nil {
		t.Error(err)
	}
	if base64.StdEncoding.EncodeToString(result) != "rS2DEDBlX8k=" {
		t.Errorf("expect: rS2DEDBlX8k=, result: %s", base64.StdEncoding.EncodeToString(result))
	}
	t.Logf("expect: rS2DEDBlX8k=, result: %s", base64.StdEncoding.EncodeToString(result))
}

func TestECBDecrypt(t *testing.T) {
	decrypter := NewTripleDESECBDecrypter()
	src, _ := base64.StdEncoding.DecodeString("rS2DEDBlX8k=")
	result, err := decrypter.Decrypt(src, key, NewPKCS5Padding())
	if err != nil {
		t.Error(err)
	}
	if string(result) != "test" {
		t.Errorf("expect: test, result: %s", result)
	}
	t.Logf("expect: test, result: %s", result)
}
