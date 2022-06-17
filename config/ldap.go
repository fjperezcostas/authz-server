package config

type Ldap struct {
	Url    string `yaml:"url"`
	BaseDn string `yaml:"base-dn"`
	Admin  Admin  `yaml:"admin"`
}

type Admin struct {
	User     string `yaml:"user"`
	Password string `yaml:"password"`
}
