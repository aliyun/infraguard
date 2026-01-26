// Package auth provides cloud credential management.
package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aliyun/infraguard/pkg/i18n"
)

// Credentials holds cloud provider credentials.
type Credentials struct {
	AccessKeyID     string
	AccessKeySecret string
	Region          string
}

// AliyunConfig represents the Aliyun CLI configuration file structure.
type AliyunConfig struct {
	Current  string          `json:"current"`
	Profiles []AliyunProfile `json:"profiles"`
}

// AliyunProfile represents a single profile in Aliyun CLI config.
type AliyunProfile struct {
	Name            string `json:"name"`
	Mode            string `json:"mode"`
	AccessKeyID     string `json:"access_key_id"`
	AccessKeySecret string `json:"access_key_secret"`
	RegionID        string `json:"region_id"`
}

// aliyunConfigPath returns the path to Aliyun CLI config file.
func aliyunConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".aliyun", "config.json")
}

// LoadCredentials loads credentials from Aliyun CLI configuration.
func LoadCredentials() (*Credentials, error) {
	msg := i18n.Msg()
	configPath := aliyunConfigPath()
	if configPath == "" {
		return nil, fmt.Errorf("%s", msg.Errors.UnableToDetermineHomeDir)
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf(msg.Errors.AliyunConfigNotFound, configPath)
		}
		return nil, fmt.Errorf(msg.Errors.ReadAliyunConfig, err)
	}

	var config AliyunConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf(msg.Errors.ParseAliyunConfig, err)
	}

	// Find the current profile
	var currentProfile *AliyunProfile
	for i := range config.Profiles {
		if config.Profiles[i].Name == config.Current {
			currentProfile = &config.Profiles[i]
			break
		}
	}

	if currentProfile == nil {
		return nil, fmt.Errorf(msg.Errors.ProfileNotFound, config.Current)
	}

	if currentProfile.AccessKeyID == "" || currentProfile.AccessKeySecret == "" {
		return nil, fmt.Errorf(msg.Errors.InvalidAccessKey, config.Current)
	}

	return &Credentials{
		AccessKeyID:     currentProfile.AccessKeyID,
		AccessKeySecret: currentProfile.AccessKeySecret,
		Region:          currentProfile.RegionID,
	}, nil
}
