package config

import (
	"encoding/json"
	"os"
)

func LoadConfig(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	err = json.Unmarshal(data, &Config)
	if err != nil {
		return err
	}

	return nil
}
