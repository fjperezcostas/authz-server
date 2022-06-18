package oauth2

import (
	"fmt"
	"net/http"

	"authzserver/config"
)

func Login(w http.ResponseWriter, r *http.Request, config config.Application) {
	protocol := r.Header.Get("x-forwarded-proto")
	host := r.Header.Get("x-forwarded-host")
	path := r.URL.Path
	cookie := &http.Cookie{
		Name:  config.Cookies.OriginalUri,
		Value: fmt.Sprintf("%v://%v%v", protocol, host, path),
		Path:  "/",
	}
	http.SetCookie(w, cookie)
	http.Redirect(w, r, config.OAuth2.Login.Url, http.StatusFound)
}
