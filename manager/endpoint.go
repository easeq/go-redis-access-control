package manager

import (
	"errors"
	"log"
)

// Action defines the endpoints action config
type Action struct {
	// Can access without authentication
	Unauthenticated bool
	// Roles that can access the resource
	Roles map[string]bool
}

// Endpoint path
type Endpoint string

// Endpoints map of Endpoint and it's config
type Endpoints map[Endpoint]Action

var (
	// ErrInvalidEndpoint returned when accessing an invalid endpoint
	ErrInvalidEndpoint = errors.New("accessing invalid endpoint")

	// registeredEndpoints is a list of registered endpoints
	registeredEndpoints Endpoints
)

func init() {
	registeredEndpoints = make(Endpoints)
}

// Register - adds a new endpoint and it's action
func (e Endpoint) Register(action Action) {
	registeredEndpoints[e] = action
}

// CanAccessWithRole returrns whether the given endpoint is accessible with the users permissions
//
// The method returns false when the action is un-registered or
// the user doesn't have enough permissions
//
// Returns true otherwise
func (e Endpoint) CanAccessWithRole(role string) bool {
	action, err := e.getAction()
	if err != nil {
		log.Println(err)
		return false
	}

	return action.Roles[role]
}

// CanAccessWithoutAuth checks if the endpoint can be accessed without authentication
func (e Endpoint) CanAccessWithoutAuth() bool {
	action, err := e.getAction()
	if err != nil {
		log.Println(err)
		return false
	}

	return action.Unauthenticated == true
}

func (e Endpoint) getAction() (*Action, error) {
	action, ok := registeredEndpoints[e]
	if !ok {
		return nil, ErrInvalidEndpoint
	}

	return &action, nil
}
