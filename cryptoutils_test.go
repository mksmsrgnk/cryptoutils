package cryptoutils

import (
	"encoding/base64"
	"github.com/mksmsrgnk/padding"
	"testing"
)

var (
	iv               = []byte("myivmyivmyivmyiv")
	AESCBCCryptogram = "Fenn4u0yKIBiy7usB9/OpA=="
)

func TestAesCBCEncrypt(t *testing.T) {
	result := NewAES(key).NewCBC(iv,
		padding.NewPKCS5()).Encrypt([]byte("test"))
	if result.Error != nil {
		t.Error(result.Error)
	}
	if base64.StdEncoding.EncodeToString(result.Data) != AESCBCCryptogram {
		t.Errorf("expect: %s, got: %s",
			AESCBCCryptogram, string(result.Data))
	}
}

func TestAesCBCDecrypt(t *testing.T) {
	data, err := base64.StdEncoding.DecodeString(AESCBCCryptogram)
	if err != nil {
		t.Error(err)
	}
	result := NewAES(key).NewCBC(iv, padding.NewPKCS5()).Decrypt(data)
	if string(result.Data) != "test" {
		t.Errorf("expect: test, got: %s", string(result.Data))
	}
}
