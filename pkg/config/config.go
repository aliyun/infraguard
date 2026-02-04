// Package config provides configuration management for InfraGuard CLI.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aliyun/infraguard/pkg/i18n"
	"gopkg.in/yaml.v3"
)

// Config represents the CLI configuration.
type Config struct {
	Lang string `yaml:"lang,omitempty"`
}

// ValidKeys contains all valid configuration keys.
var ValidKeys = []string{"lang"}

// ValidLangValues contains valid values for the lang key.
var ValidLangValues = []string{"en", "zh", "es", "fr", "de", "ja", "pt"}

// configFileName is the name of the configuration file.
const configFileName = "config.yaml"

// DefaultConfigDir returns the default configuration directory.
func DefaultConfigDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf(i18n.Msg().Errors.GetHomeDirectory, err)
	}
	return filepath.Join(homeDir, ".infraguard"), nil
}

// ConfigPath returns the full path to the configuration file.
func ConfigPath() (string, error) {
	configDir, err := DefaultConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, configFileName), nil
}

// Load reads the configuration from the config file.
// Returns an empty Config if the file doesn't exist.
func Load() (*Config, error) {
	configPath, err := ConfigPath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{}, nil
		}
		return nil, fmt.Errorf(i18n.Msg().Errors.ReadConfigFile, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf(i18n.Msg().Errors.ParseConfigFile, err)
	}

	return &cfg, nil
}

// Save writes the configuration to the config file.
func Save(cfg *Config) error {
	configPath, err := ConfigPath()
	if err != nil {
		return err
	}

	// Ensure the config directory exists
	configDir := filepath.Dir(configPath)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf(i18n.Msg().Errors.CreateConfigDir, err)
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf(i18n.Msg().Errors.MarshalConfig, err)
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf(i18n.Msg().Errors.WriteConfigFile, err)
	}

	return nil
}

// Get returns the value for the given key.
// Returns empty string if the key is not set.
func (c *Config) Get(key string) string {
	switch key {
	case "lang":
		return c.Lang
	default:
		return ""
	}
}

// Set sets the value for the given key.
func (c *Config) Set(key, value string) {
	switch key {
	case "lang":
		c.Lang = value
	}
}

// Unset removes the value for the given key.
func (c *Config) Unset(key string) {
	switch key {
	case "lang":
		c.Lang = ""
	}
}

// IsEmpty returns true if the configuration has no values set.
func (c *Config) IsEmpty() bool {
	return c.Lang == ""
}

// ToMap returns the configuration as a map of key-value pairs.
// Only includes keys that have values set.
func (c *Config) ToMap() map[string]string {
	result := make(map[string]string)
	if c.Lang != "" {
		result["lang"] = c.Lang
	}
	return result
}

// IsValidKey checks if the given key is a valid configuration key.
func IsValidKey(key string) bool {
	for _, k := range ValidKeys {
		if k == key {
			return true
		}
	}
	return false
}

// IsValidLang checks if the given value is a valid language.
func IsValidLang(value string) bool {
	for _, v := range ValidLangValues {
		if v == value {
			return true
		}
	}
	return false
}

// ValidateValue validates the value for the given key.
// Returns an error if the value is invalid.
func ValidateValue(key, value string) error {
	msg := i18n.Msg()
	switch key {
	case "lang":
		if !IsValidLang(value) {
			return fmt.Errorf(msg.Config.Errors.InvalidValue, key, value, strings.Join(ValidLangValues, ", "))
		}
	}
	return nil
}

// GetLang returns the configured language.
// Returns empty string if not set.
func GetLang() string {
	cfg, err := Load()
	if err != nil {
		return ""
	}
	return cfg.Lang
}
