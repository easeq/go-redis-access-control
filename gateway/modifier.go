package gateway

import (
	"context"
	"encoding/gob"
	"fmt"
	"log"
	"net/http"
	"strconv"

	"github.com/easeq/go-redis-access-control/manager"
	"github.com/gorilla/sessions"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/rbcervilla/redisstore/v8"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/runtime/protoiface"
)

// Modifier defines a store to save session
type Modifier struct {
	store  *redisstore.RedisStore
	config *manager.Config
}

// Session is the structure holding session data that gorilla's session
// store will convert into a cookie.
type Session struct {
	// User ID
	UserID int
	// CSRF token for the session
	CSRFToken *manager.Token
	// User role
	Role string
}

const (
	// KeyUserID is identifier to get the current user's ID from the session store
	KeyUserID = "Grac-Session-User-Id"
	// KeyUserRole is the identifier to get the current user's role from the session store
	KeyUserRole = "Grac-Session-User-Role"
	// KeyDeleteSession is the identifier to check whether the session should be deleted
	KeyDeleteSession = "Grac-Is-Delete-Session"
	// KeyAuthorization is the key to look for the authorization header
	KeyAuthorization = "authorization"
	// KeyUserCSRFToken is the identifier for csrf token
	KeyUserCSRFToken = "X-Xsrf-Token"
	// ErrFailedTokenGeneration is to show when the token generation fails
	ErrFailedTokenGeneration = "GRAC Error: Failed to generate access token"
)

func init() {
	gob.Register(&Session{})
}

// NewModifier returns a gateway input/output modifier
func NewModifier(store *redisstore.RedisStore, config interface{}) *Modifier {
	return &Modifier{store, config.(*manager.Config)}
}

// MetadataAnnotator looks up session and passes session data and jwt token to gRPC method
func (m *Modifier) MetadataAnnotator(ctx context.Context, r *http.Request) metadata.MD {
	session, err := m.store.Get(r, m.config.Redis.DefaultSessionID)
	if err != nil {
		// Session doesn't exist, hence no metadata to pass to gRPC method
		return metadata.Pairs()
	}

	sessionDataValue, ok := session.Values["data"]
	if !ok {
		return metadata.Pairs()
	}

	sessionData := sessionDataValue.(*Session)
	// Generate JWT
	jwt, err := m.config.JWT.Generate(sessionData.UserID, sessionData.Role, sessionData.CSRFToken)
	if err != nil {
		log.Println(ErrFailedTokenGeneration)
		log.Println(err)
		return metadata.Pairs()
	}

	// Set user id, role and jwt (csrf token passed directly from http request)
	return metadata.Pairs(
		KeyUserID, strconv.Itoa(sessionData.UserID),
		KeyUserRole, sessionData.Role,
		KeyAuthorization, jwt,
		KeyUserCSRFToken, r.Header.Get(KeyUserCSRFToken),
	)
}

// ResponseModifier checks whether the gRPC method called has requested for changing the response
// before the http response is sent
func (m *Modifier) ResponseModifier(ctx context.Context, w http.ResponseWriter, resp protoiface.MessageV1) error {
	md, ok := runtime.ServerMetadataFromContext(ctx)
	if !ok {
		return nil
	}

	deleteSession, _ := isDeleteSession(md)
	userID, _ := getUserID(md)
	role, _ := getUserRole(md)

	// Get HTTP request saved in context, and attach session to it
	request := getRequestFromContext(ctx)
	session, err := m.prepareSession(request, userID, role, deleteSession)
	if err != nil {
		return err
	}

	if sessionDataValue, ok := session.Values["data"]; ok && deleteSession != true {
		sessionData := sessionDataValue.(*Session)
		w.Header().Set(KeyUserCSRFToken, sessionData.CSRFToken.ToURLSafeString())
	}

	// Delete gRPC data that should not be passed as headers in the HTTP response
	deleteGrpcMetadata(w, KeyUserID, KeyUserRole, KeyDeleteSession, KeyUserCSRFToken)

	// Save the session
	return m.store.Save(request, w, session)
}

func deleteGrpcMetadata(w http.ResponseWriter, keys ...string) {
	for _, key := range keys {
		delete(w.Header(), "Grpc-Metadata-"+key)
	}
}

func (m *Modifier) prepareSession(req *http.Request, userID int, role string, deleteSession bool) (*sessions.Session, error) {
	session, err := m.store.New(req, m.config.Redis.DefaultSessionID)
	if err != nil {
		return nil, err
	}

	if session.IsNew == true {
		session.Options.Domain = m.config.Redis.SessionDomain
		session.Options.Path = "/"
		session.Options.SameSite = http.SameSiteLaxMode
		session.Options.HttpOnly = true
		session.Options.Secure = m.config.Redis.SecureCookie

		csrfToken, err := manager.NewToken(m.config.Redis.CSRFTokenLength)
		if err != nil {
			return nil, err
		}

		sessionData := &Session{
			UserID:    userID,
			CSRFToken: csrfToken,
			Role:      role,
		}

		session.Values["data"] = sessionData
	}

	session.Options.MaxAge = getSessionTimeout(
		deleteSession,
		m.config.Redis.SessionTimeout,
	)

	return session, nil
}

// GetRequestFromContext pulls the request from context (set in middleware above)
func GetRequestFromContext(ctx context.Context) *http.Request {
	return ctx.Value(requestContextKey).(*http.Request)
}

// getSessionTimeout returns the session timeout value set in env
func getSessionTimeout(delete bool, timeout int) int {
	if delete {
		return -1
	}

	return timeout
}

// getUserID returns the current session user ID
func getUserID(md runtime.ServerMetadata) (int, error) {
	userID, _ := metadataByKey(md, KeyUserID)
	if userID == "" {
		return 0, fmt.Errorf("Invalid user")
	}

	return strconv.Atoi(userID)
}

// getUserRole returns the current session user role
func getUserRole(md runtime.ServerMetadata) (string, error) {
	return metadataByKey(md, KeyUserRole)
}

// isDeleteSession returns whether to delete the existing session or not
func isDeleteSession(md runtime.ServerMetadata) (bool, error) {
	delete, _ := metadataByKey(md, KeyDeleteSession)
	if delete == "" {
		return false, nil
	}

	return strconv.ParseBool(delete)
}

// metadataByKey returns the value of the first metadata with the provided key
func metadataByKey(md runtime.ServerMetadata, key string) (string, error) {
	values := md.HeaderMD.Get(key)
	if len(values) == 0 {
		return "", fmt.Errorf("Value %s is required", key)
	}

	return values[0], nil
}
