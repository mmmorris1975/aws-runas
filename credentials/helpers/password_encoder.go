package helpers

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/crypto/scrypt"
	"strconv"
	"strings"
)

// The base64 StdEncoding alphabet, copied from the base64 package
const encodeStd = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

type passwordEncoder struct {
	r, p, keyLen int

	key []byte
	b32 *base32.Encoding
	b64 *base64.Encoding
}

// NewPasswordEncoder creates a new password encoder using the provided key for the encryption.
// The password encoding logic is meant for obfuscation of the data and not a replacement for real encryption
func NewPasswordEncoder(key []byte) *passwordEncoder {
	return &passwordEncoder{
		key:    key,
		r:      8,
		p:      1,
		keyLen: aes.BlockSize,
		b32:    base32.StdEncoding.WithPadding(base32.NoPadding),
		b64:    base64.RawStdEncoding,
	}
}

// Encode takes the provided password data and creates an encrypted value of "cost" complexity
func (e *passwordEncoder) Encode(pw string, cost uint8) (string, error) {
	enc := strings.Builder{}
	enc.WriteString(e.encode(pw))

	if m := enc.Len() % e.keyLen; m != 0 {
		for i := 0; i < e.keyLen-m; i++ {
			// pad it out
			enc.WriteRune('=')
		}
	}

	salt, err := generateSalt(8)
	if err != nil {
		return "", err
	}

	c, err := e.cipher(salt, cost)
	if err != nil {
		return "", err
	}

	ciphertext, err := initCipherText(enc.Len())
	if err != nil {
		return "", err
	}

	mode := cipher.NewCBCEncrypter(c, ciphertext[:e.keyLen])
	mode.CryptBlocks(ciphertext[e.keyLen:], []byte(enc.String()))

	return fmt.Sprintf("%x$%s$%s", cost, e.b32.EncodeToString(salt), e.b64.EncodeToString(ciphertext)), nil
}

func (e *passwordEncoder) encode(s string) string {
	return rot32(e.b64.EncodeToString([]byte(s)))
}

// Decode takes the string, which is the output from Encode() and decrypts the data
func (e *passwordEncoder) Decode(s string) (string, error) {
	sp := strings.Split(s, "$")
	if len(sp) < 3 {
		return "", errors.New("invalid input")
	}

	cost, err := strconv.ParseInt(sp[0], 16, 8)
	if err != nil {
		return "", err
	}

	salt, err := e.b32.DecodeString(sp[1])
	if err != nil {
		return "", err
	}

	c, err := e.cipher(salt, uint8(cost))
	if err != nil {
		return "", err
	}

	ciphertext, err := e.b64.DecodeString(sp[2])
	if err != nil {
		return "", err
	}

	mode := cipher.NewCBCDecrypter(c, ciphertext[:e.keyLen])

	ciphertext = ciphertext[e.keyLen:]
	mode.CryptBlocks(ciphertext, ciphertext)

	plaintext, err := e.decode(strings.TrimRight(string(ciphertext), `=`))
	if err != nil {
		return "", err
	}

	return plaintext, nil
}

func (e *passwordEncoder) decode(s string) (string, error) {
	b, err := e.b64.DecodeString(rot32(s))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (e *passwordEncoder) cipher(salt []byte, cost uint8) (cipher.Block, error) {
	b, err := scrypt.Key(e.key, salt, 1<<cost, e.r, e.p, e.keyLen)
	if err != nil {
		return nil, err
	}
	return aes.NewCipher(b)
}

// input value is a base64 string (ala passwordEncoder.encode())
func rot32(s string) string {
	return strings.Map(func(r rune) rune {
		n := strings.IndexRune(encodeStd, r)
		v := (n + len(encodeStd)/2) % len(encodeStd)
		return rune(encodeStd[v])
	}, s)
}

func generateSalt(n uint8) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

func initCipherText(n int) ([]byte, error) {
	ct := make([]byte, aes.BlockSize+n)
	iv := ct[:aes.BlockSize]
	_, err := rand.Read(iv)
	return ct, err
}
