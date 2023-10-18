package config

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

type AuthzServer struct {
	Http   Http   `yaml:"http"`
	OAuth2 OAuth2 `yaml:"oauth2"`
	Ldap   Ldap   `yaml:"ldap"`
	Jwt    Jwt    `yaml:"jwt"`
}

func (s *AuthzServer) UnmarshallYaml(data []byte) error {
	if err := yaml.Unmarshal(data, &s); err != nil {
		return err
	}
	s.OAuth2.Login.Url = fmt.Sprintf(s.OAuth2.Login.Url, s.OAuth2.Client.Id, s.OAuth2.Login.RedirectUri, s.OAuth2.Login.ResponseType, s.OAuth2.Login.Scope)
	return nil
}
