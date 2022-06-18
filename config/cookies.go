package config

type Cookies struct {
	AuthToken   string `yaml:"auth-token"`
	OriginalUri string `yaml:"original-uri"`
	DisplayName string `yaml:"display-name"`
}
