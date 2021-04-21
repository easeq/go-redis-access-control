package manager

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"io"
	"log"
)

type CSRF struct {
	Key        []byte `env:"GRAC_CSRF_KEY"`
	RandLength int    `env:"GRAC_CSRF_RANDOM_LENGTH,default=10"`
}

// Token struct hold the token
type Token struct {
	*CSRF
	sessId string
}

// Generate an HMAC token with session id and timestamp
func (c *CSRF) Create(sessId string) *Token {
	return &Token{c, sessId}
}

// Get returns the byte representation of the the Token
// HMAC(sessId + Random(10))
// Token(HMAC() + Random(10))
func (t *Token) Get(randN []byte) []byte {
	mac := hmac.New(sha512.New, t.Key)
	mac.Write(t.GetMessage(string(randN)))

	return append(mac.Sum(nil), randN...)
}

// GetMessage returns the message to HMAC
func (t *Token) GetMessage(random string) []byte {
	return []byte(fmt.Sprintf("%s:%s", t.sessId, random))
}

// ToURLSafeString returns a base64 encoded URL safe token string
func (t *Token) ToURLSafeString(randN []byte) string {
	return base64.URLEncoding.EncodeToString(t.Get(randN))
}

// String returns a token string
func (t *Token) String(randN []byte) string {
	return string(t.Get(randN))
}

// Compare request HMAC with calculated HMAC
func (t *Token) Validate(hmacWithTs string) bool {
	decodedHmacWithTs, err := base64.URLEncoding.DecodeString(hmacWithTs)
	if err != nil {
		log.Printf("Error decoding HMAC string: %s\n", err)
		return false
	}

	// Get the last RandLength characters from string
	messageHmac := decodedHmacWithTs[0 : len(decodedHmacWithTs)-t.RandLength]
	randN := decodedHmacWithTs[len(decodedHmacWithTs)-t.RandLength:]

	// Generate HMAC using session ID and timestamp from the request
	expectedHmac := t.Get(randN)

	return hmac.Equal(messageHmac, expectedHmac)
}

// GenerateRandomBytes returns securely generated random bytes.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}

func init() {
	// Assert that a cryptographically secure PRNG is available.
	buf := make([]byte, 1)

	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		panic(fmt.Sprintf("crypto/rand is unavailable: Read() failed with %#v", err))
	}
}
