package manager

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

func init() {
	// Assert that a cryptographically secure PRNG is available.
	buf := make([]byte, 1)

	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		panic(fmt.Sprintf("crypto/rand is unavailable: Read() failed with %#v", err))
	}
}

// Token struct hold the token
type Token struct {
	token []byte
}

// NewToken creates a new token
func NewToken(n int) (*Token, error) {
	token, err := GenerateRandomBytes(n)
	if err != nil {
		return nil, fmt.Errorf("Token generation error: %v", err)
	}
	return &Token{token}, nil
}

// ToURLSafeString returns a base64 encoded URL safe random string
func (t *Token) ToURLSafeString() string {
	return base64.URLEncoding.EncodeToString(t.token)
}

// ToString converts and returns the string representation
// of the generated token
func (t *Token) ToString() string {
	return string(t.token)
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
