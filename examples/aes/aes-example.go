package main 

import (
	"fmt"
	"strings"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
)

func AES_CBC_Encrypt(key, val string) string {
	var bkey []byte
	if (len(key) < 16) {
		panic(errors.New("Key must be at least 16 bytes"))
	} else {
		bkey = []byte(key[:16])
	}
	
	padding := aes.BlockSize - len(val) % aes.BlockSize
	data := val + strings.Repeat(string(padding), padding)
	crypted := make([]byte, len(data))
	block, err := aes.NewCipher(bkey)
	if err != nil {
		panic(err)
	}
	iv := bkey
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(crypted, []byte(data))
	return base64.StdEncoding.EncodeToString(crypted)
}


func AES_CBC_Decrypt(key, val string) string {
	var bkey []byte
	if (len(key) < 16) {
		panic(errors.New("Key must be at least 16 bytes"))
	} else {
		bkey = []byte(key[:16])
	}
	crypted, _ := base64.StdEncoding.DecodeString(val)
	block, err := aes.NewCipher(bkey)
	if err != nil {
		panic(err)
	}
	iv := bkey
	
	mode := cipher.NewCBCDecrypter(block, iv)
	// dst and src can be the same to work inplace
	mode.CryptBlocks(crypted, crypted)
	padding := crypted[len(crypted)-1]
	// trim off the padding
	return strings.TrimRight(string(crypted), string(padding))
}

func main() {
	fmt.Println("AES CBS with PKCS7 padding example")
	key := "asixteenbyteskey"
	plaintext := "the brown fox jumps over the brown fence"
	fmt.Println(AES_CBC_Encrypt(key, plaintext))
	data := AES_CBC_Decrypt(key, "6XZRL1oT/kMy3nuhF7zBAujGj3Ndkg+gcSXXpuzufZTYw2f44x6AZpG8U6bfXM/D")
	fmt.Println(data)
}

