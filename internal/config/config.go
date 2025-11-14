package config

import (
	"os"

	"gopkg.in/yaml.v2"
)

type Config struct {
	VirusTotalAPIKey string `yaml:"virustotal_api_key"`
	KeytaroAPIKey    string `yaml:"keytaro_api_key"`
	KeytaroURL       string `yaml:"keitaro_url"`
	TelegramBotToken string `yaml:"telegram_bot_token"`
}

func LoadConfig() (*Config, error) {
	data, err := os.ReadFile("config.yml")
	if err != nil {
		return nil, err
	}

	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}
