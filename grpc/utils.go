package grpc

import (
	"github.com/easeq/go-redis-access-control/gateway"
	"github.com/easeq/go-redis-access-control/manager"
	"google.golang.org/grpc/metadata"
)

// GetAuthCreds returns a random string, csrf token and access token
func GetAuthCreds(id int64, role string, sessID string) (string, *manager.Token, string, error) {
	config, err := manager.NewConfig()
	if err != nil {
		return "", nil, "", err
	}

	randN, err := manager.GenerateRandomString(config.CSRF.RandLength)
	if err != nil {
		return "", nil, "", err
	}

	csrfToken := config.CSRF.Create(sessID)
	accessToken, err := config.JWT.Generate(0, role, csrfToken)
	if err != nil {
		return "", nil, "", err
	}

	return randN, csrfToken, accessToken, nil
}

// GetAuthMD is a helper method to return authorization creds
func GetAuthMD(id int64, role string, sessID string) (metadata.MD, error) {
	randN, csrfToken, accessToken, err := GetAuthCreds(id, role, sessID)
	if err != nil {
		return nil, err
	}

	md := metadata.New(map[string]string{
		gateway.KeyAuthorization: accessToken,
		gateway.KeySessionID:     sessID,
		gateway.KeyUserCSRFToken: csrfToken.ToURLSafeString(randN, true),
	})

	return md, nil
}
