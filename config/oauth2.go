package config

type OAuth2 struct {
	Client   Client   `yaml:"client"`
	Login    Login    `yaml:"login"`
	Token    Token    `yaml:"token"`
	UserInfo UserInfo `yaml:"user-info"`
}

type Client struct {
	Id     string `yaml:"id"`
	Secret string `yaml:"secret"`
}

type Login struct {
	Url          string `yaml:"url"`
	RedirectUri  string `yaml:"redirect-uri"`
	ResponseType string `yaml:"response-type"`
	Scope        string `yaml:"scope"`
}

type Token struct {
	Url       string `yaml:"url"`
	GrantType string `yaml:"grant-type"`
}

type UserInfo struct {
	Url string `yaml:"url"`
}
