package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"sniproxy/internal/router"
)

type Config struct {
	Listen         string  `yaml:"listen"`
	DefaultBackend string  `yaml:"default_backend"`
	Routes         []Route `yaml:"routes"`

	r *router.Router
}

type Route struct {
	SNI     []string `yaml:"sni"`
	Backend string   `yaml:"backend"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.Listen == "" {
		cfg.Listen = ":443"
	}
	if cfg.DefaultBackend == "" {
		return nil, fmt.Errorf("default_backend is required")
	}
	cfg.r = buildRouter(cfg.Routes, cfg.DefaultBackend)
	return cfg, nil
}

func buildRouter(routes []Route, defaultBackend string) *router.Router {
	m := make(map[string][]string, len(routes))
	for _, rt := range routes {
		m[rt.Backend] = append(m[rt.Backend], rt.SNI...)
	}
	return router.New(m, defaultBackend)
}

// Reload re-reads the config file. On parse error, returns the original cfg unchanged.
func Reload(path string, cfg *Config) (*Config, error) {
	newCfg, err := Load(path)
	if err != nil {
		return cfg, err
	}
	return newCfg, nil
}

func (c *Config) Router() *router.Router { return c.r }
