package ldap

import (
	"authzserver/config"
	"fmt"

	"github.com/go-ldap/ldap"
)

type User struct {
	Dn          string
	DisplayName string
	Mail        string
}

func SearchUserByUid(uid string, ldapConfig config.Ldap) (*User, error) {
	l, err := ldap.DialURL(ldapConfig.Url)
	if err != nil {
		return nil, err
	}
	defer l.Close()
	bind := fmt.Sprintf("cn=%v, %v", ldapConfig.Admin.User, ldapConfig.BaseDn)
	err = l.Bind(bind, ldapConfig.Admin.Password)
	if err != nil {
		return nil, err
	}
	filter := fmt.Sprintf("(uid=%s)", ldap.EscapeFilter(uid))
	request := ldap.NewSearchRequest(ldapConfig.BaseDn, ldap.ScopeWholeSubtree, 0, 0, 0, false, filter, []string{"dn", "displayName", "mail"}, []ldap.Control{})
	results, err := l.Search(request)
	if err != nil {
		return nil, err
	}
	if len(results.Entries) == 0 {
		return nil, nil
	}
	return &User{
		Dn:          results.Entries[0].DN,
		DisplayName: results.Entries[0].Attributes[0].Values[0],
		Mail:        results.Entries[0].Attributes[1].Values[0],
	}, nil
}
