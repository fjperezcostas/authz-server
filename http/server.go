package http

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"

	"authzserver/config"
	"authzserver/ldap"
	"authzserver/oauth2"
)

type Server struct {
	Config *config.Server
}

func NewServer(configFile string) (*Server, error) {
	yaml, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, err
	}
	s := &Server{Config: &config.Server{}}
	if err = s.Config.UnmarshallYaml(yaml); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Server) Start() error {
	http.HandleFunc("/", s.root)
	http.HandleFunc("/oauth2/callback", s.oauth2callback)
	log.Println(fmt.Sprintf("authz server listening port %v...", s.Config.Http.Port))
	return http.ListenAndServe(fmt.Sprintf(":%v", s.Config.Http.Port), nil)
}

func (s *Server) root(w http.ResponseWriter, r *http.Request) {
	session := Session{}
	cookie, _ := r.Cookie(s.Config.Http.SessionId)
	err := session.LoadCookie(cookie)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	session.RequestedUrl = r.Header.Get("x-requested-url")
	if session.Token == "" {
		s.redirectTo(w, r, s.Config.OAuth2.Login.Url, session)
		return
	}
	user, err := oauth2.GetUserInfo(session.Token, s.Config.OAuth2)
	if err != nil {
		log.Println(err)
		s.redirectTo(w, r, s.Config.OAuth2.Login.Url, session)
		return
	}
	var ldapUser *ldap.User
	ldapUser, err = ldap.SearchUserByUid(user.Id, s.Config.Ldap)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if ldapUser != nil {
		session.UserInfo.Id = user.Id
		session.UserInfo.DisplayName = ldapUser.DisplayName
		cookie, err = session.BuildCookie(s.Config.Http.SessionId)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, cookie)
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusForbidden)
	}
}

func (s *Server) oauth2callback(w http.ResponseWriter, r *http.Request) {
	var request *http.Request
	var response *http.Response
	var body []byte

	cookie, err := r.Cookie(s.Config.Http.SessionId)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	session := Session{}
	if err := session.LoadCookie(cookie); err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	err = r.ParseForm()
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusBadRequest)
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
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err = client.Do(request)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	body, err = ioutil.ReadAll(response.Body)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if response.StatusCode != 200 {
		log.Print(fmt.Errorf("wrong status code received from Google authz server. Status: %v, body: %v", response.StatusCode, string(body)))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	tokenResponse := &oauth2.Token{}
	err = json.Unmarshal(body, tokenResponse)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	session.Token = tokenResponse.AccessToken
	s.redirectTo(w, r, session.RequestedUrl, session)
}

func (s *Server) redirectTo(w http.ResponseWriter, r *http.Request, url string, session Session) {
	cookie, err := session.BuildCookie(s.Config.Http.SessionId)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, cookie)
	http.Redirect(w, r, url, http.StatusFound)
}
