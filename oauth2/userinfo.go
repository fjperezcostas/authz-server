package oauth2

import (
	"authzserver/config"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

type UserInfo struct {
	Id            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Picture       string `json:"picture"`
}

func GetUserInfo(token string, config config.OAuth2) (*UserInfo, error) {
	var response *http.Response
	client := &http.Client{}
	request, err := http.NewRequest("GET", config.UserInfo.Url, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %v", token))
	response, err = client.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode == 401 {
		return nil, &UnauthorizedTokenError{}
	}
	var body []byte
	body, err = ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	user := &UserInfo{}
	err = json.Unmarshal(body, user)
	if err != nil {
		return nil, err
	}
	return user, nil
}
