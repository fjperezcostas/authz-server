package oauth2

import "fmt"

type UnauthorizedTokenError struct {
	token string
}

func (e *UnauthorizedTokenError) Error() string {
	return fmt.Sprintf("HTTP status 401: unauthorized token %v", e.token)
}
