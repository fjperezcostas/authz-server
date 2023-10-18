package main

import (
	"authzserver/http"
	"flag"
)

func main() {
	configFile := flag.String("config", "config.yml", "sets the config file")
	flag.Parse()
	s, err := http.NewAuthzServer(*configFile)
	if err != nil {
		panic(err)
	}
	if err = s.Start(); err != nil {
		panic(err)
	}
}
