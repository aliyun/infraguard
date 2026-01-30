package ros

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFromEnv(t *testing.T) {
	tests := []struct {
		name       string
		envVars    map[string]string
		wantNil    bool
		wantKeyID  string
		wantRegion string
	}{
		{
			name: "standard environment variables",
			envVars: map[string]string{
				"ALIBABA_CLOUD_ACCESS_KEY_ID":     "test_key",
				"ALIBABA_CLOUD_ACCESS_KEY_SECRET": "test_secret",
				"ALIBABA_CLOUD_REGION_ID":         "cn-beijing",
			},
			wantNil:    false,
			wantKeyID:  "test_key",
			wantRegion: "cn-beijing",
		},
		{
			name: "alternative environment variables",
			envVars: map[string]string{
				"ALICLOUD_ACCESS_KEY": "test_alt_key",
				"ALICLOUD_SECRET_KEY": "alt_secret",
			},
			wantNil:    false,
			wantKeyID:  "test_alt_key",
			wantRegion: "cn-hangzhou", // default
		},
		{
			name:    "no environment variables",
			envVars: map[string]string{},
			wantNil: true,
		},
		{
			name: "only access key ID",
			envVars: map[string]string{
				"ALIBABA_CLOUD_ACCESS_KEY_ID": "test_key",
			},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear all relevant environment variables
			clearEnvVars := []string{
				"ALIBABA_CLOUD_ACCESS_KEY_ID",
				"ALIBABA_CLOUD_ACCESS_KEY_SECRET",
				"ALIBABA_CLOUD_REGION_ID",
				"ALICLOUD_ACCESS_KEY",
				"ALICLOUD_SECRET_KEY",
			}
			for _, key := range clearEnvVars {
				os.Unsetenv(key)
			}

			// Set test environment variables
			for key, val := range tt.envVars {
				os.Setenv(key, val)
			}
			defer func() {
				for key := range tt.envVars {
					os.Unsetenv(key)
				}
			}()

			cred := loadFromEnv()

			if tt.wantNil {
				if cred != nil {
					t.Errorf("loadFromEnv() = %v, want nil", cred)
				}
				return
			}

			if cred == nil {
				t.Fatal("loadFromEnv() = nil, want non-nil")
			}

			if cred.AccessKeyID != tt.wantKeyID {
				t.Errorf("AccessKeyID = %v, want %v", cred.AccessKeyID, tt.wantKeyID)
			}
			if cred.Region != tt.wantRegion {
				t.Errorf("Region = %v, want %v", cred.Region, tt.wantRegion)
			}
		})
	}
}

func TestLoadFromCLIConfig(t *testing.T) {
	// Create temporary config file
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, ".aliyun")
	os.Mkdir(configDir, 0755)
	configPath := filepath.Join(configDir, "config.json")

	// Override home directory for testing
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", originalHome)

	tests := []struct {
		name         string
		config       *cliConfig
		wantErr      bool
		wantKeyID    string
		wantType     string
		wantRegion   string
		noConfigFile bool
	}{
		{
			name: "access key authentication",
			config: &cliConfig{
				Current: "default",
				Profiles: []cliProfile{
					{
						Name:            "default",
						Mode:            "AK",
						AccessKeyID:     "test_config_key",
						AccessKeySecret: "config_secret",
						RegionID:        "cn-shanghai",
					},
				},
			},
			wantErr:    false,
			wantKeyID:  "test_config_key",
			wantType:   "AK",
			wantRegion: "cn-shanghai",
		},
		{
			name: "sts token authentication",
			config: &cliConfig{
				Current: "sts-profile",
				Profiles: []cliProfile{
					{
						Name:            "sts-profile",
						AccessKeyID:     "test_sts_key",
						AccessKeySecret: "sts_secret",
						StsToken:        "sts_token_value",
						RegionID:        "cn-hangzhou",
					},
				},
			},
			wantErr:    false,
			wantKeyID:  "test_sts_key",
			wantType:   "sts",
			wantRegion: "cn-hangzhou",
		},
		{
			name: "ram role authentication",
			config: &cliConfig{
				Current: "ram-profile",
				Profiles: []cliProfile{
					{
						Name:            "ram-profile",
						Mode:            "RamRoleArn",
						AccessKeyID:     "test_ram_key",
						AccessKeySecret: "ram_secret",
						RamRoleArn:      "acs:ram::123456:role/test-role",
						RamSessionName:  "test-session",
						RegionID:        "cn-beijing",
					},
				},
			},
			wantErr:    false,
			wantKeyID:  "test_ram_key",
			wantType:   "RamRoleArn",
			wantRegion: "cn-beijing",
		},
		{
			name: "default profile when current not set",
			config: &cliConfig{
				Profiles: []cliProfile{
					{
						Name:            "default",
						AccessKeyID:     "test_default_key",
						AccessKeySecret: "default_secret",
					},
				},
			},
			wantErr:    false,
			wantKeyID:  "test_default_key",
			wantType:   "access_key",
			wantRegion: "cn-hangzhou", // default
		},
		{
			name: "missing access key",
			config: &cliConfig{
				Current: "invalid",
				Profiles: []cliProfile{
					{
						Name:            "invalid",
						AccessKeySecret: "secret_only",
					},
				},
			},
			wantErr: true,
		},
		{
			name:         "config file not exists",
			noConfigFile: true,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.noConfigFile {
				// Write config file
				data, _ := json.MarshalIndent(tt.config, "", "  ")
				if err := os.WriteFile(configPath, data, 0600); err != nil {
					t.Fatalf("failed to write test config: %v", err)
				}
			} else {
				// Remove config file
				os.Remove(configPath)
			}

			cred, err := loadFromCLIConfig()

			if tt.wantErr {
				if err == nil {
					t.Error("loadFromCLIConfig() error = nil, want error")
				}
				return
			}

			if err != nil {
				t.Fatalf("loadFromCLIConfig() error = %v, want nil", err)
			}

			if cred.AccessKeyID != tt.wantKeyID {
				t.Errorf("AccessKeyID = %v, want %v", cred.AccessKeyID, tt.wantKeyID)
			}
			if cred.Type != tt.wantType {
				t.Errorf("Type = %v, want %v", cred.Type, tt.wantType)
			}
			if cred.Region != tt.wantRegion {
				t.Errorf("Region = %v, want %v", cred.Region, tt.wantRegion)
			}
		})
	}
}

func TestLoadCredentials_Priority(t *testing.T) {
	// Setup: create CLI config file
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, ".aliyun")
	os.Mkdir(configDir, 0755)
	configPath := filepath.Join(configDir, "config.json")

	config := &cliConfig{
		Current: "default",
		Profiles: []cliProfile{
			{
				Name:            "default",
				AccessKeyID:     "test_config_key",
				AccessKeySecret: "config_secret",
				RegionID:        "cn-beijing", // Config file region
			},
		},
	}
	data, _ := json.MarshalIndent(config, "", "  ")
	os.WriteFile(configPath, data, 0600)

	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", originalHome)

	t.Run("env vars take precedence for credentials", func(t *testing.T) {
		// Test: environment variables should take precedence
		os.Setenv("ALIBABA_CLOUD_ACCESS_KEY_ID", "test_env_key")
		os.Setenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET", "env_secret")
		defer func() {
			os.Unsetenv("ALIBABA_CLOUD_ACCESS_KEY_ID")
			os.Unsetenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET")
			os.Unsetenv("ALIBABA_CLOUD_REGION_ID")
		}()

		cred, err := LoadCredentials()
		if err != nil {
			t.Fatalf("LoadCredentials() error = %v", err)
		}

		if cred.AccessKeyID != "test_env_key" {
			t.Errorf("expected environment variable to take precedence, got AccessKeyID = %v", cred.AccessKeyID)
		}
	})

	t.Run("region falls back to config file when env region not set", func(t *testing.T) {
		// Clear any region env var
		os.Unsetenv("ALIBABA_CLOUD_REGION_ID")

		// Set credentials in env but not region
		os.Setenv("ALIBABA_CLOUD_ACCESS_KEY_ID", "test_env_key")
		os.Setenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET", "env_secret")
		defer func() {
			os.Unsetenv("ALIBABA_CLOUD_ACCESS_KEY_ID")
			os.Unsetenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET")
		}()

		cred, err := LoadCredentials()
		if err != nil {
			t.Fatalf("LoadCredentials() error = %v", err)
		}

		// Should use region from config file
		if cred.Region != "cn-beijing" {
			t.Errorf("expected region from config file (cn-beijing), got %v", cred.Region)
		}
	})

	t.Run("env region takes precedence over config file", func(t *testing.T) {
		// Set both credentials and region in env
		os.Setenv("ALIBABA_CLOUD_ACCESS_KEY_ID", "test_env_key")
		os.Setenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET", "env_secret")
		os.Setenv("ALIBABA_CLOUD_REGION_ID", "cn-shanghai")
		defer func() {
			os.Unsetenv("ALIBABA_CLOUD_ACCESS_KEY_ID")
			os.Unsetenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET")
			os.Unsetenv("ALIBABA_CLOUD_REGION_ID")
		}()

		cred, err := LoadCredentials()
		if err != nil {
			t.Fatalf("LoadCredentials() error = %v", err)
		}

		// Should use region from env
		if cred.Region != "cn-shanghai" {
			t.Errorf("expected region from env var (cn-shanghai), got %v", cred.Region)
		}
	})
}

func TestCredentialConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *CredentialConfig
		wantErr bool
	}{
		{
			name: "valid credentials",
			config: &CredentialConfig{
				AccessKeyID:     "test_valid_key_123",
				AccessKeySecret: "valid_secret",
			},
			wantErr: false,
		},
		{
			name: "missing access key ID",
			config: &CredentialConfig{
				AccessKeySecret: "secret",
			},
			wantErr: true,
		},
		{
			name: "missing access key secret",
			config: &CredentialConfig{
				AccessKeyID: "test_key",
			},
			wantErr: true,
		},
		{
			name: "invalid access key ID format",
			config: &CredentialConfig{
				AccessKeyID:     "short",
				AccessKeySecret: "secret",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMaskSecret(t *testing.T) {
	tests := []struct {
		name   string
		secret string
		want   string
	}{
		{
			name:   "normal secret",
			secret: "abcdefghijklmnop",
			want:   "abcd****mnop",
		},
		{
			name:   "short secret",
			secret: "short",
			want:   "****",
		},
		{
			name:   "minimum maskable",
			secret: "12345678",
			want:   "****",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MaskSecret(tt.secret)
			if got != tt.want {
				t.Errorf("MaskSecret() = %v, want %v", got, tt.want)
			}
		})
	}
}
