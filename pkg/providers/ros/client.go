package ros

import (
	"fmt"
	"sync"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	ros "github.com/alibabacloud-go/ros-20190910/v4/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/aliyun/infraguard/pkg/i18n"
)

var (
	clientInstance *ros.Client
	clientOnce     sync.Once
	clientErr      error
)

// NewClient creates a new ROS SDK client with the provided credentials
func NewClient(cred *CredentialConfig) (*ros.Client, error) {
	msg := i18n.Msg()
	if err := cred.Validate(); err != nil {
		return nil, fmt.Errorf(msg.Errors.ROSInvalidCredentials, err)
	}

	config := &openapi.Config{
		AccessKeyId:     tea.String(cred.AccessKeyID),
		AccessKeySecret: tea.String(cred.AccessKeySecret),
		Endpoint:        tea.String("ros.aliyuncs.com"),
		RegionId:        tea.String(cred.Region),
	}

	// Add security token if present (for STS)
	if cred.SecurityToken != "" {
		config.SecurityToken = tea.String(cred.SecurityToken)
	}

	client, err := ros.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf(msg.Errors.ROSFailedCreateClient, err)
	}

	return client, nil
}

// GetClient returns a singleton ROS client instance
// This avoids creating multiple clients for the same credentials
func GetClient(cred *CredentialConfig) (*ros.Client, error) {
	clientOnce.Do(func() {
		clientInstance, clientErr = NewClient(cred)
	})

	if clientErr != nil {
		return nil, clientErr
	}

	return clientInstance, nil
}

// ResetClient resets the singleton client (useful for testing)
func ResetClient() {
	clientInstance = nil
	clientOnce = sync.Once{}
	clientErr = nil
}
