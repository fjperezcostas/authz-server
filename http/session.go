package http

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
)

type Session struct {
	Token        string   `json:"token"`
	RequestedUrl string   `json:"requested-url"`
	UserInfo     UserInfo `json:"user-info"`
}

type UserInfo struct {
	Id          string `json:"id"`
	DisplayName string `json:"display-name"`
}

func (s *Session) LoadCookie(cookie *http.Cookie) error {
	if cookie != nil {
		cookieValue, err := base64.StdEncoding.DecodeString(cookie.Value)
		if err != nil {
			return err
		}
		err = json.Unmarshal(cookieValue, s)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Session) BuildCookie(cookieId string) (*http.Cookie, error) {
	sessionValue, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	return &http.Cookie{
		Name:  cookieId,
		Value: base64.StdEncoding.EncodeToString(sessionValue),
		Path:  "/",
	}, nil
}
