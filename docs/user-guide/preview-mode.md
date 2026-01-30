# Preview Mode

Preview mode uses Alibaba Cloud ROS PreviewStack API to validate templates against real-time cloud resources and configurations, providing more accurate compliance checks compared to static analysis.

## Overview

InfraGuard supports two scan modes:

- **Static Mode** (default): Fast local analysis of template syntax and structure
- **Preview Mode**: Cloud-based validation using ROS PreviewStack API

## When to Use Preview Mode

Use preview mode when you need:

- Validation against actual cloud resource configurations
- More accurate compliance assessment

Use static mode when you need:

- Fast offline scanning
- Quick compliance checks
- CI/CD pipeline integration without cloud credentials

## Prerequisites

Preview mode requires:

1. **Alibaba Cloud Account** with ROS access
2. **Valid Credentials** (AccessKey, STS Token, or RAM Role)
3. **Network Access** to `ros.aliyuncs.com`
4. **Permissions**: `ros:PreviewStack` action

## Configuration

### Method 1: Environment Variables (Recommended)

```bash
export ALIBABA_CLOUD_ACCESS_KEY_ID="****"
export ALIBABA_CLOUD_ACCESS_KEY_SECRET="****"
export ALIBABA_CLOUD_REGION_ID="cn-hangzhou"  # optional
```

### Method 2: Aliyun CLI Configuration

```bash
# Configure aliyun CLI
aliyun configure

# Or manually edit ~/.aliyun/config.json
{
  "current": "default",
  "profiles": [
    {
      "name": "default",
      "mode": "AK",
      "access_key_id": "****",
      "access_key_secret": "****",
      "region_id": "cn-hangzhou"
    }
  ]
}
```

## Supported Authentication Methods

### AccessKey (AK/SK)

**Environment Variables:**
```bash
export ALIBABA_CLOUD_ACCESS_KEY_ID="****"
export ALIBABA_CLOUD_ACCESS_KEY_SECRET="****"
```

**CLI Config:**
```json
{
  "mode": "AK",
  "access_key_id": "****",
  "access_key_secret": "****"
}
```

### STS Token

**Environment Variables:**
```bash
export ALIBABA_CLOUD_ACCESS_KEY_ID="STS.****"
export ALIBABA_CLOUD_ACCESS_KEY_SECRET="****"
export ALIBABA_CLOUD_SECURITY_TOKEN="****"
```

**CLI Config:**
```json
{
  "mode": "StsToken",
  "access_key_id": "STS.****",
  "access_key_secret": "****",
  "sts_token": "****"
}
```

### RAM Role

**CLI Config:**
```json
{
  "mode": "RamRoleArn",
  "access_key_id": "****",
  "access_key_secret": "****",
  "ram_role_arn": "acs:ram::****:role/RoleName",
  "ram_session_name": "session-name"
}
```

## Usage

### Basic Usage

```bash
# Scan with preview mode
infraguard scan template.yaml --mode preview

# Scan with specific policy
infraguard scan template.yaml --mode preview -p pack:aliyun:quick-start-compliance-pack

# Generate HTML report
infraguard scan template.yaml --mode preview --format html -o report.html
```

### With Template Parameters

```bash
# Pass parameters as key-value pairs
infraguard scan template.yaml --mode preview \
  -i InstanceType=ecs.g6.large \
  -i ImageId=centos_7

# Pass parameters from JSON file
infraguard scan template.yaml --mode preview -i params.json
```

## Credential Priority

InfraGuard loads credentials in the following order:

1. **Environment Variables** (highest priority)
2. **Aliyun CLI Configuration** (`~/.aliyun/config.json`)

If credentials are found in environment variables, CLI configuration will be ignored.

## See Also

- [Scanning Templates](scanning-templates.md)
- [Managing Policies](managing-policies.md)
- [CLI Reference](../cli/scan.md)
- [ROS PreviewStack API](https://www.alibabacloud.com/help/en/ros/developer-reference/api-ros-2019-09-10-previewstack)
