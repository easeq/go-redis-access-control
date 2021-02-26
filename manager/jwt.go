package manager

import (
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
	jwtGo "github.com/dgrijalva/jwt-go"
)

// JWT is a JSON web token manager
type JWT struct {
	secretKey string        `env:"GRAL_JWT_SECRET_KEY"`
	duration  time.Duration `env:"GRAL_JWT_DURATION"`
}

// Claims defines the custom JWT claims
type Claims struct {
	jwt.StandardClaims
	ID          int    `json:"ID"`
	Role        string `json:"roles"`
	RandomToken string `json:"token"`
}

// NewJWTManager returns a new JWT manager
func NewJWTManager(secretKey string, tokenDuration time.Duration) *JWT {
	return &JWT{secretKey, tokenDuration}
}

// GetSecretKey returns secret key to sign jwt
func (jwt *JWT) GetSecretKey() []byte {
	return []byte(jwt.secretKey)
}

// Generate generates and signs a new token with specified claims for a user
func (jwt *JWT) Generate(ID int, role string, randToken string) (string, error) {
	claims := Claims{
		ID:          ID,
		Role:        role,
		RandomToken: randToken,
		StandardClaims: jwtGo.StandardClaims{
			ExpiresAt: time.Now().Add(jwt.duration).Unix(),
		},
	}

	token := jwtGo.NewWithClaims(jwtGo.SigningMethodHS512, claims)
	return token.SignedString(jwt.GetSecretKey())
}

// Verify verifies the access token string and return a user claim if the token is valid
func (jwt *JWT) Verify(tokenStr string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwtGo.ParseWithClaims(tokenStr, claims, func(token *jwtGo.Token) (interface{}, error) {
		return jwt.GetSecretKey(), nil
	})

	if err != nil || !token.Valid {
		return nil, fmt.Errorf("Invalid token: %w", err)
	}

	return claims, nil
}
