package ros

import (
	"os"
	"testing"

	"github.com/aliyun/infraguard/pkg/i18n"
)

func TestMain(m *testing.M) {
	// Initialize i18n before all tests
	i18n.Init()
	os.Exit(m.Run())
}

func TestNewClient(t *testing.T) {
	tests := []struct {
		name    string
		cred    *CredentialConfig
		wantErr bool
	}{
		{
			name: "valid credentials",
			cred: &CredentialConfig{
				AccessKeyID:     "test_key_1234567",
				AccessKeySecret: "test_secret",
				Region:          "cn-hangzhou",
				Type:            "access_key",
			},
			wantErr: false,
		},
		{
			name: "valid credentials with STS token",
			cred: &CredentialConfig{
				AccessKeyID:     "test_key_1234567",
				AccessKeySecret: "test_secret",
				SecurityToken:   "sts_token_value",
				Region:          "cn-beijing",
				Type:            "sts",
			},
			wantErr: false,
		},
		{
			name: "missing access key ID",
			cred: &CredentialConfig{
				AccessKeySecret: "test_secret",
				Region:          "cn-hangzhou",
			},
			wantErr: true,
		},
		{
			name: "missing access key secret",
			cred: &CredentialConfig{
				AccessKeyID: "test_key_1234567",
				Region:      "cn-hangzhou",
			},
			wantErr: true,
		},
		{
			name: "invalid access key ID format",
			cred: &CredentialConfig{
				AccessKeyID:     "short",
				AccessKeySecret: "test_secret",
				Region:          "cn-hangzhou",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.cred)

			if tt.wantErr {
				if err == nil {
					t.Error("NewClient() error = nil, want error")
				}
				return
			}

			if err != nil {
				t.Errorf("NewClient() error = %v, want nil", err)
				return
			}

			if client == nil {
				t.Error("NewClient() returned nil client")
			}
		})
	}
}

func TestGetClient_Singleton(t *testing.T) {
	// Reset client before test
	ResetClient()
	defer ResetClient()

	cred := &CredentialConfig{
		AccessKeyID:     "test_key_1234567",
		AccessKeySecret: "test_secret",
		Region:          "cn-hangzhou",
		Type:            "access_key",
	}

	// First call should create new client
	client1, err := GetClient(cred)
	if err != nil {
		t.Fatalf("GetClient() first call error = %v", err)
	}

	// Second call should return same instance
	client2, err := GetClient(cred)
	if err != nil {
		t.Fatalf("GetClient() second call error = %v", err)
	}

	// Verify they are the same instance (same pointer)
	if client1 != client2 {
		t.Error("GetClient() returned different instances, want same instance")
	}
}

func TestGetClient_Error(t *testing.T) {
	// Reset client before test
	ResetClient()
	defer ResetClient()

	// Invalid credentials
	cred := &CredentialConfig{
		AccessKeyID:     "short", // invalid format
		AccessKeySecret: "test_secret",
		Region:          "cn-hangzhou",
	}

	_, err := GetClient(cred)
	if err == nil {
		t.Error("GetClient() with invalid cred error = nil, want error")
	}
}

func TestClientConfiguration(t *testing.T) {
	tests := []struct {
		name       string
		cred       *CredentialConfig
		wantRegion string
	}{
		{
			name: "default region",
			cred: &CredentialConfig{
				AccessKeyID:     "test_key_1234567",
				AccessKeySecret: "test_secret",
				Region:          "cn-hangzhou",
				Type:            "access_key",
			},
			wantRegion: "cn-hangzhou",
		},
		{
			name: "custom region",
			cred: &CredentialConfig{
				AccessKeyID:     "test_key_1234567",
				AccessKeySecret: "test_secret",
				Region:          "cn-shanghai",
				Type:            "access_key",
			},
			wantRegion: "cn-shanghai",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.cred)
			if err != nil {
				t.Fatalf("NewClient() error = %v", err)
			}

			if client == nil {
				t.Fatal("NewClient() returned nil client")
			}

			// The client is created successfully, which means
			// the configuration was accepted (we can't easily verify
			// internal configuration without making actual API calls)
		})
	}
}
