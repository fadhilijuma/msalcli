package config

import (
	_ "embed"
	"log"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ClientId string `yaml:"client_id"`
	Port     string `yaml:"port"`
	TenantId string `yaml:"tenant_id"`
	Secret   string `yaml:"secret"`
}

//go:embed config.yml
var ymlConfig []byte
var cfg Config

func New() *Config {
	err := yaml.Unmarshal(ymlConfig, &cfg)
	if err != nil {
		log.Fatal(err)
	}
	return &cfg
}
