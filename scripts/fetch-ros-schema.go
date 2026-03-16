// Script to fetch ROS resource type schema from Alibaba Cloud ROS API.
// Usage: go run scripts/fetch-ros-schema.go [-output path/to/ros_resources.json]
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	ros "github.com/alibabacloud-go/ros-20190910/v4/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/aliyun/infraguard/pkg/lsp/schema"
)

func main() {
	output := flag.String("output", "pkg/lsp/schema/data/ros_resources.json", "Output file path")
	flag.Parse()

	client, err := createClient()
	if err != nil {
		log.Fatalf("Failed to create ROS client: %v", err)
	}

	count, err := schema.FetchAndSave(client, &schema.FetchOptions{
		OutputPath: *output,
		Logger:     log.Printf,
	})
	if err != nil {
		log.Fatalf("Failed to fetch schema: %v", err)
	}

	log.Printf("Schema written to %s (%d resource types)", *output, count)
}

func createClient() (*ros.Client, error) {
	accessKeyID := os.Getenv("ALIBABA_CLOUD_ACCESS_KEY_ID")
	accessKeySecret := os.Getenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET")
	if accessKeyID == "" || accessKeySecret == "" {
		return nil, fmt.Errorf("set ALIBABA_CLOUD_ACCESS_KEY_ID and ALIBABA_CLOUD_ACCESS_KEY_SECRET")
	}

	config := &openapi.Config{
		AccessKeyId:     tea.String(accessKeyID),
		AccessKeySecret: tea.String(accessKeySecret),
		Endpoint:        tea.String("ros.aliyuncs.com"),
	}
	return ros.NewClient(config)
}
