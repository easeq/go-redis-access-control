package gateway

import (
	"context"
	"encoding/gob"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"

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

// SessionMetadata is a key => value map of additional data saved in the session
type SessionMetadata map[string]string

// Session is the structure holding session data that gorilla's session
// store will convert into a cookie.
type Session struct {
	// User ID
	UserID int
	// CSRF token for the session
	CSRFToken *manager.Token
	// User role
	Role string
	// Metadata
	Metadata SessionMetadata
}

const (
	// SessionDataPrefix is the prefix that gRPC needs to use to set session data
	SessionDataPrefix = "Grac-Session-User-"
	// KeyUserID is identifier to get the current user's ID from the session store
	KeyUserID = "Id"
	// KeyUserRole is the identifier to get the current user's role from the session store
	KeyUserRole = "Role"
	// KeyDeleteSession is the identifier to check whether the session should be deleted
	KeyDeleteSession = "Grac-Is-Delete-Session"
	// KeyAuthorization is the key to look for the authorization header
	KeyAuthorization = "authorization"
	// KeyUserCSRFToken is the identifier for csrf token
	KeyUserCSRFToken = "X-Xsrf-Token"
	// KeyGrpcMetadata is the key attached by gRPC gateway for the metadata sent by gRPC method
	KeyGrpcMetadata = "Grpc-Metadata-"
)

var (
	// ErrFailedTokenGeneration is to show when the token generation fails
	ErrFailedTokenGeneration = errors.New("GRAC Error: Failed to generate access token")
	// ErrUserIDOrRoleNotProvided returned when session creation is requested without UserID and Role
	ErrUserIDOrRoleNotProvided = errors.New("Session requires a UserID and Role")
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

	// Get data saved in the session
	sessionData, ok := getSessionData(session)
	if !ok {
		return metadata.Pairs()
	}

	// Generate JWT
	jwt, err := m.config.JWT.Generate(sessionData.UserID, sessionData.Role, sessionData.CSRFToken)
	if err != nil {
		log.Println(ErrFailedTokenGeneration)
		log.Println(err)
		return metadata.Pairs()
	}

	// Set user id, role and jwt (csrf token passed directly from http request)
	md := metadata.Pairs(
		KeyUserID, strconv.Itoa(sessionData.UserID),
		KeyUserRole, sessionData.Role,
		KeyAuthorization, jwt,
		KeyUserCSRFToken, r.Header.Get(KeyUserCSRFToken),
	)

	// Append session metadata to gRPC metadata
	for k, v := range sessionData.Metadata {
		md.Append(SessionDataPrefix+k, v)
	}

	return md
}

// ResponseModifier checks whether the gRPC method called has requested for changing the response
// before the http response is sent
func (m *Modifier) ResponseModifier(ctx context.Context, w http.ResponseWriter, resp protoiface.MessageV1) error {
	md, ok := runtime.ServerMetadataFromContext(ctx)
	if !ok {
		return nil
	}

	deleteSession, _ := isDeleteSession(md)

	// Get HTTP request saved in context, and attach session to it
	request := GetRequestFromContext(ctx)
	session, err := m.prepareSession(request, deleteSession, md.HeaderMD)
	if err != nil {
		return err
	}

	if sessionDataValue, ok := session.Values["data"]; ok && !deleteSession {
		sessionData := sessionDataValue.(*Session)
		w.Header().Set(KeyUserCSRFToken, sessionData.CSRFToken.ToURLSafeString())
	}

	// Save the session
	return m.store.Save(request, w, session)
}

// Prepare http session
func (m *Modifier) prepareSession(
	req *http.Request,
	deleteSession bool,
	md metadata.MD,
) (*sessions.Session, error) {
	// Get the saved session for the request, from redis store
	session, err := m.store.New(req, m.config.Redis.DefaultSessionID)
	if err != nil {
		return nil, err
	}

	// Prepare session data from gRPC metadata
	sessionData, err := prepareSessionData(md)
	if err != nil {
		return nil, err
	}

	if session.IsNew {
		session.Options.Domain = m.config.Redis.SessionDomain
		session.Options.Path = "/"
		session.Options.SameSite = http.SameSite(m.config.Redis.SameSite)
		session.Options.HttpOnly = true
		session.Options.Secure = m.config.Redis.SecureCookie

		csrfToken, err := manager.NewToken(m.config.Redis.CSRFTokenLength)
		if err != nil {
			return nil, err
		}
		sessionData.CSRFToken = csrfToken

		// if sessionData.UserID <= 0 || sessionData.Role == "" {
		// 	return nil, ErrUserIDOrRoleNotProvided
		// }

		session.Values["data"] = sessionData
	} else {
		// Get old session data stored in the session
		oldSessionData, ok := getSessionData(session)
		if ok {
			// Only update the session metdata.
			// UserID, Role and CSRFToken cannot be modified
			for k, v := range sessionData.Metadata {
				oldSessionData.Metadata[k] = v
			}
		}
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

// GetMetadataKey returns the prepared key for session metadata
func GetMetadataKey(key string) string {
	return SessionDataPrefix + key
}

// getSessionTimeout returns the session timeout value set in env
func getSessionTimeout(delete bool, timeout int) int {
	if delete {
		return -1
	}

	return timeout
}

// isDeleteSession returns whether to delete the existing session or not
func isDeleteSession(md runtime.ServerMetadata) (bool, error) {
	values := md.HeaderMD.Get(KeyDeleteSession)
	if len(values) == 0 {
		return false, nil
	}

	return strconv.ParseBool(values[0])
}

// getSessionData returns the data saved in the session
func getSessionData(session *sessions.Session) (*Session, bool) {
	sessionDataValue, ok := session.Values["data"]
	if !ok {
		return nil, false
	}

	return sessionDataValue.(*Session), true
}

// prepareSessionData returns all the session related data
func prepareSessionData(mds metadata.MD) (*Session, error) {
	sessionData := new(Session)
	for k, v := range mds {
		if !strings.HasPrefix(k, SessionDataPrefix) {
			continue
		}

		key := strings.TrimPrefix(k, SessionDataPrefix)
		switch key {
		case KeyUserID:
			userID, err := strconv.Atoi(v[0])
			if err != nil {
				return nil, err
			}
			sessionData.UserID = userID
		case KeyUserRole:
			sessionData.Role = v[0]
		default:
			sessionData.Metadata[key] = v[0]
		}
	}

	return sessionData, nil
}
