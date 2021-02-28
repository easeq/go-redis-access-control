package gateway

import (
	"context"
	"fmt"
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

// NewModifier returns a gateway input/output modifier
func NewModifier(store *redisstore.RedisStore, config *manager.Config) *Modifier {
	return &Modifier{store, config}
}

// MetadataAnnotator looks up session and passes session data and jwt token to gRPC method
func (m *Modifier) MetadataAnnotator(_ context.Context, r *http.Request) metadata.MD {
	session, err := m.store.Get(r, m.config.Redis.DefaultSessionID)
	if err != nil {
		// Session doesn't exist, hence no metadata to pass to gRPC method
		return metadata.Pairs()
	}

	if sessionDataValue, ok := session.Values["data"]; ok {
		sessionData := sessionDataValue.(*Session)
		// Generate JWT
		jwt, err := m.config.JWT.Generate(sessionData.UserID, sessionData.Role, sessionData.CSRFToken.ToString())
		if err != nil {
			return metadata.Pairs()
		}

		// Set user id and jwt (csrf token passed directly from http request)
		return metadata.Pairs(
			"userId", strconv.Itoa(sessionData.UserID),
			"authorization", jwt,
		)
	}

	return metadata.Pairs()
}

// ResponseModifier checks whether the gRPC method called has requested for changing the response
// before the http response is sent
func (m *Modifier) ResponseModifier(ctx context.Context, w http.ResponseWriter, resp protoiface.MessageV1) error {
	md, ok := runtime.ServerMetadataFromContext(ctx)
	if !ok {
		return nil
	}

	userID, err := getUserID(md)
	if err != nil || userID == 0 {
		return err
	}

	role, err := getUserRole(md)
	if err != nil || role == "" {
		return nil
	}

	deleteSession, err := isDeleteSession(md)
	if err != nil {
		return err
	}

	// Get HTTP request saved in context, and attach session to it
	request := getRequestFromContext(ctx)
	session, err := m.prepareSession(request, userID, role, deleteSession)
	if err != nil {
		return err
	}

	// Save the session
	return m.store.Save(request, w, session)
}

func (m *Modifier) prepareSession(req *http.Request, userID int, role string, deleteSession bool) (*sessions.Session, error) {
	session, err := m.store.New(req, m.config.Redis.DefaultSessionID)
	if err != nil {
		return nil, err
	}

	session.Options.MaxAge = getSessionTimeout(deleteSession, m.config.Redis.SessionTimeout)
	session.Options.Path = "/"

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
	return session, nil
}

// getSessionTimeout returns the session timeout value set in env
func getSessionTimeout(delete bool, timeout int) int {
	if delete {
		return -1
	}

	return timeout
}

// pull the request from context (set in middleware above)
func getRequestFromContext(ctx context.Context) *http.Request {
	return ctx.Value(requestContextKey).(*http.Request)
}

// getUserID returns the current session user ID
func getUserID(md runtime.ServerMetadata) (int, error) {
	userID, _ := metadataByKey(md, "grac-session-user-id")
	if userID == "" {
		return 0, nil
	}

	return strconv.Atoi(userID)
}

// getUserRole returns the current session user role
func getUserRole(md runtime.ServerMetadata) (string, error) {
	return metadataByKey(md, "grac-session-user-role")
}

// isDeleteSession returns whether to delete the existing session or not
func isDeleteSession(md runtime.ServerMetadata) (bool, error) {
	gralIsDelete, err := metadataByKey(md, "grac-is-delete-session")
	if err != nil {
		return false, err
	}

	return strconv.ParseBool(gralIsDelete)
}

// metadataByKey returns the value of the first metadata with the provided key
func metadataByKey(md runtime.ServerMetadata, key string) (string, error) {
	values := md.HeaderMD.Get(key)
	if len(values) == 0 {
		return "", fmt.Errorf("Value %s is required", key)
	}

	return values[0], nil
}
