package config

type Cookies struct {
	AuthToken   string `yaml:"auth-token"`
	ForwardedTo string `yaml:"forwarded-to"`
	DisplayName string `yaml:"display-name"`
	Mail        string `yaml:"mail"`
}
