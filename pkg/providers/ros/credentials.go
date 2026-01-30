package ros

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aliyun/infraguard/pkg/i18n"
)

// CredentialConfig holds the credential configuration
type CredentialConfig struct {
	AccessKeyID     string
	AccessKeySecret string
	SecurityToken   string
	Region          string
	Type            string // AK, STS, RamRoleArn, etc.
}

// LoadCredentials loads Alibaba Cloud credentials from environment variables or CLI config file.
// Priority:
// - Credentials: Environment variables > ~/.aliyun/config.json
// - Region: ALIBABA_CLOUD_REGION_ID env var > config file region_id > default (cn-hangzhou)
func LoadCredentials() (*CredentialConfig, error) {
	// Try environment variables first for credentials
	if cred := loadFromEnv(); cred != nil {
		// If region is not set in env, try to get it from config file
		if cred.Region == "cn-hangzhou" && os.Getenv("ALIBABA_CLOUD_REGION_ID") == "" {
			if configCred, err := loadFromCLIConfig(); err == nil && configCred.Region != "" {
				cred.Region = configCred.Region
			}
		}
		return cred, nil
	}

	// Fallback to CLI config file
	return loadFromCLIConfig()
}

// loadFromEnv loads credentials from environment variables
func loadFromEnv() *CredentialConfig {
	// Check standard Alibaba Cloud environment variables
	accessKeyID := os.Getenv("ALIBABA_CLOUD_ACCESS_KEY_ID")
	accessKeySecret := os.Getenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET")

	// Check alternative environment variable names
	if accessKeyID == "" {
		accessKeyID = os.Getenv("ALICLOUD_ACCESS_KEY")
	}
	if accessKeySecret == "" {
		accessKeySecret = os.Getenv("ALICLOUD_SECRET_KEY")
	}

	// If both are set, use environment variables
	if accessKeyID != "" && accessKeySecret != "" {
		region := os.Getenv("ALIBABA_CLOUD_REGION_ID")
		if region == "" {
			region = "cn-hangzhou" // Default region
		}

		return &CredentialConfig{
			AccessKeyID:     accessKeyID,
			AccessKeySecret: accessKeySecret,
			Region:          region,
			Type:            "access_key",
		}
	}

	return nil
}

// cliConfig represents the structure of ~/.aliyun/config.json
type cliConfig struct {
	Current  string       `json:"current"`
	Profiles []cliProfile `json:"profiles"`
}

type cliProfile struct {
	Name            string `json:"name"`
	Mode            string `json:"mode"`
	AccessKeyID     string `json:"access_key_id"`
	AccessKeySecret string `json:"access_key_secret"`
	StsToken        string `json:"sts_token"`
	RamRoleArn      string `json:"ram_role_arn"`
	RamSessionName  string `json:"ram_session_name"`
	RegionID        string `json:"region_id"`
}

// loadFromCLIConfig loads credentials from ~/.aliyun/config.json
func loadFromCLIConfig() (*CredentialConfig, error) {
	msg := i18n.Msg()
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf(msg.Errors.ROSFailedGetHomeDir, err)
	}

	configPath := filepath.Join(homeDir, ".aliyun", "config.json")

	// Check if config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("%s", msg.Errors.ROSCredentialsNotFound)
	}

	// Read config file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf(msg.Errors.ROSFailedReadConfig, err)
	}

	// Parse JSON
	var config cliConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf(msg.Errors.ROSFailedParseConfig, err)
	}

	// Find the current profile
	var profile *cliProfile
	for i := range config.Profiles {
		if config.Profiles[i].Name == config.Current {
			profile = &config.Profiles[i]
			break
		}
	}

	// If current not set or not found, try to use "default" profile
	if profile == nil {
		for i := range config.Profiles {
			if config.Profiles[i].Name == "default" {
				profile = &config.Profiles[i]
				break
			}
		}
	}

	if profile == nil {
		return nil, fmt.Errorf("%s", msg.Errors.ROSNoValidProfile)
	}

	// Validate required fields
	if profile.AccessKeyID == "" {
		return nil, fmt.Errorf(msg.Errors.ROSAccessKeyIDEmpty, profile.Name)
	}
	if profile.AccessKeySecret == "" {
		return nil, fmt.Errorf(msg.Errors.ROSAccessKeySecretEmpty, profile.Name)
	}

	// Set default region if not specified
	region := profile.RegionID
	if region == "" {
		region = "cn-hangzhou"
	}

	credConfig := &CredentialConfig{
		AccessKeyID:     profile.AccessKeyID,
		AccessKeySecret: profile.AccessKeySecret,
		SecurityToken:   profile.StsToken,
		Region:          region,
		Type:            profile.Mode,
	}

	// Determine credential type based on mode and available fields
	if credConfig.Type == "" {
		if profile.StsToken != "" {
			credConfig.Type = "sts"
		} else if profile.RamRoleArn != "" {
			credConfig.Type = "ram_role_arn"
		} else {
			credConfig.Type = "access_key"
		}
	}

	return credConfig, nil
}

// Validate checks if the credential configuration is valid
func (c *CredentialConfig) Validate() error {
	msg := i18n.Msg()
	if c.AccessKeyID == "" {
		return fmt.Errorf("%s", msg.Errors.ROSAccessKeyIDRequired)
	}
	if c.AccessKeySecret == "" {
		return fmt.Errorf("%s", msg.Errors.ROSAccessKeySecretRequired)
	}
	// Basic format validation for Access Key ID (starts with LTAI)
	if len(c.AccessKeyID) < 16 {
		return fmt.Errorf("%s", msg.Errors.ROSInvalidAccessKeyFormat)
	}
	return nil
}

// MaskSecret returns a masked version of the secret for logging
func MaskSecret(secret string) string {
	if len(secret) <= 8 {
		return "****"
	}
	return secret[:4] + "****" + secret[len(secret)-4:]
}
