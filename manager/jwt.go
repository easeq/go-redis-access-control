package manager

import (
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	jwtGo "github.com/dgrijalva/jwt-go"
)

// JWT is a JSON web token manager
type JWT struct {
	SecretKey string        `env:"GRAC_JWT_SECRET_KEY"`
	Duration  time.Duration `env:"GRAC_JWT_DURATION"`
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
	return []byte(jwt.SecretKey)
}

// Generate generates and signs a new token with specified claims for a user
func (jwt *JWT) Generate(ID int, role string, randToken string) (string, error) {
	claims := Claims{
		ID:          ID,
		Role:        role,
		RandomToken: randToken,
		StandardClaims: jwtGo.StandardClaims{
			ExpiresAt: time.Now().Add(jwt.Duration).Unix(),
		},
	}

	token := jwtGo.NewWithClaims(jwtGo.SigningMethodHS512, claims)
	return token.SignedString(jwt.GetSecretKey())
}

// Verify verifies the access token string and return a user claim if the token is valid
func (jwt *JWT) Verify(tokenStr string) (*Claims, error) {
	tokenStr, err := stripBearerPrefixFromTokenString(tokenStr)
	if err != nil {
		return nil, err
	}

	claims := &Claims{}
	token, err := jwtGo.ParseWithClaims(tokenStr, claims, func(token *jwtGo.Token) (interface{}, error) {
		return jwt.GetSecretKey(), nil
	})

	if err != nil || !token.Valid {
		return nil, err
	}

	return claims, nil
}

// Strips 'Bearer ' prefix from bearer token string
func stripBearerPrefixFromTokenString(token string) (string, error) {
	if len(token) > 6 && strings.ToUpper(token[0:7]) == "BEARER " {
		return token[7:], nil
	}
	return token, nil
}
