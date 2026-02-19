package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

const (
	DefaultAPIURL = "https://api.shireguard.com"
	configDir     = ".shireguard"
	configFile    = "config.json"
)

type Config struct {
	APIURL       string `json:"api_url"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	DeviceID     string `json:"device_id"`
	DeviceName   string `json:"device_name"`
	NetworkID    string `json:"network_id"`
	PrivateKey   string `json:"private_key"`
	PublicKey    string `json:"public_key"`
	AssignedIP   string `json:"assigned_ip"`
	Email        string `json:"email"`
}

func Dir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, configDir), nil
}

func Load() (*Config, error) {
	dir, err := Dir()
	if err != nil {
		return nil, err
	}

	path := filepath.Join(dir, configFile)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{APIURL: DefaultAPIURL}, nil
		}
		return nil, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	if cfg.APIURL == "" {
		cfg.APIURL = DefaultAPIURL
	}

	return &cfg, nil
}

func (c *Config) Save() error {
	dir, err := Dir()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}

	path := filepath.Join(dir, configFile)
	return os.WriteFile(path, data, 0600)
}

func (c *Config) IsLoggedIn() bool {
	return c.AccessToken != "" && c.RefreshToken != ""
}

func (c *Config) IsRegistered() bool {
	return c.DeviceID != "" && c.PrivateKey != ""
}

func (c *Config) Clear() {
	c.AccessToken = ""
	c.RefreshToken = ""
	c.DeviceID = ""
	c.DeviceName = ""
	c.NetworkID = ""
	c.PrivateKey = ""
	c.PublicKey = ""
	c.AssignedIP = ""
	c.Email = ""
}
