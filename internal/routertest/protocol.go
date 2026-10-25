// Package routertest supplies wire-protocol helpers for local mock-router tests.
// Production code must not import it.
package routertest

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
)

type Payload struct {
	Content string `json:"content"`
	Key     string `json:"key,omitempty"`
	IV      string `json:"iv"`
}

func EncryptCBC(key, iv, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padding := aes.BlockSize - len(plain)%aes.BlockSize
	padded := append(append([]byte(nil), plain...), bytes.Repeat([]byte{byte(padding)}, padding)...)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(padded, padded)
	return padded, nil
}

func DecryptCBC(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("router response could not be decrypted")
	}
	plain := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ciphertext)
	padding := int(plain[len(plain)-1])
	if padding < 1 || padding > aes.BlockSize || padding > len(plain) {
		return nil, errors.New("router response contained invalid padding")
	}
	for _, b := range plain[len(plain)-padding:] {
		if int(b) != padding {
			return nil, errors.New("router response contained invalid padding")
		}
	}
	return plain[:len(plain)-padding], nil
}

func WriteEncrypted(t *testing.T, w http.ResponseWriter, key []byte, value any) {
	t.Helper()
	plain, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := EncryptCBC(key, iv, plain)
	if err != nil {
		t.Fatal(err)
	}
	_ = json.NewEncoder(w).Encode(Payload{IV: base64.StdEncoding.EncodeToString(iv), Content: base64.StdEncoding.EncodeToString(ciphertext)})
}
