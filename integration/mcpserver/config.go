package main

import (
	"fmt"
	"os"

	"github.com/0ndreu/aoa"
	"gopkg.in/yaml.v3"
)

// Config is the root config.yaml schema.
type Config struct {
	Server         ServerConfig              `yaml:"server"`
	ActiveProvider string                    `yaml:"active_provider"`
	Providers      map[string]ProviderConfig `yaml:"providers"`
	Downstream     DownstreamConfig          `yaml:"downstream"`
}

type ServerConfig struct {
	Addr     string    `yaml:"addr"`
	Resource string    `yaml:"resource"`
	TLS      TLSConfig `yaml:"tls"`
}

type TLSConfig struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

type ProviderConfig struct {
	Issuer         string         `yaml:"issuer"`
	JWKSURI        string         `yaml:"jwks_uri"`       // optional; else discovered
	TokenEndpoint  string         `yaml:"token_endpoint"` // optional; else discovered
	Audience       []string       `yaml:"audience"`
	RequiredScopes []string       `yaml:"required_scopes"`
	DPoP           string         `yaml:"dpop"` // off | optional | required
	Exchange       ExchangeConfig `yaml:"exchange"`
}

type ExchangeConfig struct {
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
}

type DownstreamConfig struct {
	URL      string   `yaml:"url"`
	Audience []string `yaml:"audience"`
}

// DPoPMode maps the config string onto aoa's DPoPMode.
func (p ProviderConfig) DPoPMode() aoa.DPoPMode {
	switch p.DPoP {
	case "required":
		return aoa.DPoPRequired
	case "optional":
		return aoa.DPoPOptional
	default:
		return aoa.DPoPOff
	}
}

// LoadConfig reads path, expands ${ENV} references, and unmarshals YAML.
func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	expanded := os.Expand(string(raw), os.Getenv)
	var cfg Config
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.ActiveProvider == "" {
		return nil, fmt.Errorf("config: active_provider is required")
	}
	return &cfg, nil
}

// Active returns the selected provider profile, or an error if missing.
func (c *Config) Active() (ProviderConfig, error) {
	p, ok := c.Providers[c.ActiveProvider]
	if !ok {
		return ProviderConfig{}, fmt.Errorf("config: active_provider %q not found in providers", c.ActiveProvider)
	}
	if p.Issuer == "" {
		return ProviderConfig{}, fmt.Errorf("config: provider %q has no issuer", c.ActiveProvider)
	}
	return p, nil
}
