package main

import (
	"os"

	"gopkg.in/yaml.v3"

	"github.com/dbut2/auth/go/auth"
)

func ConfigFromFile(filename string) (auth.Config, error) {
	bytes, err := os.ReadFile(filename)
	if err != nil {
		return auth.Config{}, err
	}

	var config auth.Config
	err = yaml.Unmarshal(bytes, &config)
	if err != nil {
		return auth.Config{}, err
	}

	return config, nil
}
