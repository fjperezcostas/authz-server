package http

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/dgrijalva/jwt-go"

	"authzserver/config"
	"authzserver/ldap"
	"authzserver/oauth2"
)

type AuthzServer struct {
	Config *config.AuthzServer
}

func NewAuthzServer(configFile string) (*AuthzServer, error) {
	yaml, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, err
	}
	s := &AuthzServer{Config: &config.AuthzServer{}}
	if err = s.Config.UnmarshallYaml(yaml); err != nil {
		return nil, err
	}
	http.HandleFunc("/", s.root)
	http.HandleFunc("/oauth2/callback", s.oauth2callback)
	return s, nil
}

func (s *AuthzServer) Start() error {
	log.Println(fmt.Sprintf("authz server listening port %v...", s.Config.Http.Port))
	return http.ListenAndServe(fmt.Sprintf(":%v", s.Config.Http.Port), nil)
}

func (s *AuthzServer) root(w http.ResponseWriter, r *http.Request) {
	session := Session{}
	cookie, _ := r.Cookie(s.Config.Http.SessionId)
	if err := session.LoadCookie(cookie); err != nil {
		s.handleError(w, err, http.StatusInternalServerError)
		return
	}
	session.RequestedUrl = r.Header.Get("x-requested-url")
	if session.Token == "" {
		s.redirectTo(w, r, s.Config.OAuth2.Login.Url, session)
		return
	}
	token, err := jwt.Parse(session.Token, func(token *jwt.Token) (interface{}, error) {
		return []byte(s.Config.Jwt.Secret), nil
	})
	if err != nil {
		s.handleError(w, err, http.StatusUnauthorized)
		return
	}
	if !token.Valid {
		err = fmt.Errorf("provided token is not valid")
		s.handleError(w, err, http.StatusUnauthorized)
		return
	}
	sub := ""
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		sub = claims["sub"].(string)
	} else {
		err = fmt.Errorf("unable to obtain subject from received token")
		s.handleError(w, err, http.StatusInternalServerError)
		return
	}
	var ldapUser *ldap.User
	ldapUser, err = ldap.SearchUserByUid(sub, s.Config.Ldap)
	if err != nil {
		s.handleError(w, err, http.StatusInternalServerError)
		return
	}
	if ldapUser == nil {
		err = fmt.Errorf("LDAP user with subject %v was not found in database", sub)
		s.handleError(w, err, http.StatusForbidden)
		return
	}
	session.UserInfo.Id = sub
	session.UserInfo.DisplayName = ldapUser.DisplayName
	cookie, err = session.BuildCookie(s.Config.Http.SessionId)
	if err != nil {
		s.handleError(w, err, http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, cookie)
	w.WriteHeader(http.StatusOK)
}

func (s *AuthzServer) oauth2callback(w http.ResponseWriter, r *http.Request) {
	var request *http.Request
	var response *http.Response
	var body []byte

	cookie, err := r.Cookie(s.Config.Http.SessionId)
	if err != nil {
		s.handleError(w, err, http.StatusInternalServerError)
		return
	}
	session := Session{}
	if err := session.LoadCookie(cookie); err != nil {
		s.handleError(w, err, http.StatusInternalServerError)
		return
	}
	err = r.ParseForm()
	if err != nil {
		s.handleError(w, err, http.StatusBadRequest)
		return
	}
	authorizationCode := r.FormValue(s.Config.OAuth2.Login.ResponseType)
	client := &http.Client{}
	formData := url.Values{
		"grant_type":    {s.Config.OAuth2.Token.GrantType},
		"code":          {authorizationCode},
		"client_id":     {s.Config.OAuth2.Client.Id},
		"client_secret": {s.Config.OAuth2.Client.Secret},
		"redirect_uri":  {s.Config.OAuth2.Login.RedirectUri},
		"access_type":   {"offline"},
	}
	request, err = http.NewRequest("POST", s.Config.OAuth2.Token.Url, strings.NewReader(formData.Encode()))
	if err != nil {
		s.handleError(w, err, http.StatusInternalServerError)
		return
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err = client.Do(request)
	if err != nil {
		s.handleError(w, err, http.StatusInternalServerError)
		return
	}
	body, err = ioutil.ReadAll(response.Body)
	if err != nil {
		s.handleError(w, err, http.StatusInternalServerError)
		return
	}
	if response.StatusCode != 200 {
		err = fmt.Errorf("wrong status code received from Google authz server. Status: %v, body: %v", response.StatusCode, string(body))
		s.handleError(w, err, http.StatusInternalServerError)
		return
	}
	tokenGoogle := &oauth2.Token{}
	err = json.Unmarshal(body, tokenGoogle)
	if err != nil {
		s.handleError(w, err, http.StatusInternalServerError)
		return
	}
	user, err := oauth2.GetUserInfo(tokenGoogle.AccessToken, s.Config.OAuth2)
	if err != nil {
		s.handleError(w, err, http.StatusInternalServerError)
		return
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": user.Id})
	session.Token, err = token.SignedString([]byte(s.Config.Jwt.Secret))
	if err != nil {
		s.handleError(w, err, http.StatusInternalServerError)
		return
	}
	s.redirectTo(w, r, session.RequestedUrl, session)
}

func (s *AuthzServer) redirectTo(w http.ResponseWriter, r *http.Request, url string, session Session) {
	cookie, err := session.BuildCookie(s.Config.Http.SessionId)
	if err != nil {
		s.handleError(w, err, http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, cookie)
	http.Redirect(w, r, url, http.StatusFound)
}

func (s *AuthzServer) handleError(w http.ResponseWriter, err error, statusCode int) {
	log.Println(fmt.Sprintf("[error] %v, returning status code %v", err, statusCode))
	w.WriteHeader(statusCode)
}
