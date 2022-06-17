package main

import "github.com/authz-server/http"

func main() {
	s, err := http.NewServer("config.yml")
	if err != nil {
		panic(err)
	}
	if err = s.Start(); err != nil {
		panic(err)
	}
}
