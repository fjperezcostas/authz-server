package oauth2

import (
	"fmt"
	"github.com/authz-server/config"
	"net/http"
)

func Login(w http.ResponseWriter, r *http.Request, config config.Config) {
	protocol := r.Header.Get("x-forwarded-proto")
	host := r.Header.Get("x-forwarded-host")
	path := r.URL.Path
	cookie := &http.Cookie{
		Name:   config.Cookies.ForwardedTo,
		Value:  fmt.Sprintf("%v://%v%v", protocol, host, path),
		Path:   "/",
		MaxAge: 30,
	}
	http.SetCookie(w, cookie)
	http.Redirect(w, r, config.OAuth2.Login.Url, http.StatusFound)
}
