package config

import (
	"fmt"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Http    Http    `yaml:"http"`
	OAuth2  OAuth2  `yaml:"oauth2"`
	Cookies Cookies `yaml:"cookies"`
	Ldap    Ldap    `yaml:"ldap"`
}

func (c *Config) UnmarshallYaml(data []byte) error {
	if err := yaml.Unmarshal(data, &c); err != nil {
		return err
	}
	c.OAuth2.Login.RedirectUri = fmt.Sprintf(c.OAuth2.Login.RedirectUri, c.Http.Port)
	c.OAuth2.Login.Url = fmt.Sprintf(c.OAuth2.Login.Url, c.OAuth2.Client.Id, c.OAuth2.Login.RedirectUri, c.OAuth2.Login.ResponseType, c.OAuth2.Login.Scope)
	return nil
}
