



package server

import (
	"crypto/subtle"
)


type Auth interface {
	CheckPasswd(string, string) (bool, error)
}

var (
	_ Auth = &SimpleAuth{}
	_ Auth = &NoAuth{}
)


type SimpleAuth struct {
	Name     string
	Password string
}

type NoAuth struct{}


func (a *SimpleAuth) CheckPasswd(name, pass string) (bool, error) {
	return constantTimeEquals(name, a.Name) && constantTimeEquals(pass, a.Password), nil
}

func (a *NoAuth) CheckPasswd(name, pass string) (bool, error) {
	return true, nil
}

func constantTimeEquals(a, b string) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
