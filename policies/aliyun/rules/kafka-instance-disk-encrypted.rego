package infraguard.rules.aliyun.kafka_instance_disk_encrypted

import rego.v1

import data.infraguard.helpers

# Rule metadata with i18n support
rule_meta := {
	"id": "rule:aliyun:kafka-instance-disk-encrypted",
	"name": {
		"en": "Kafka Instance Disk Encrypted",
		"zh": "Kafka 实例部署时启用了云盘加密",
	},
	"severity": "high",
	"description": {
		"en": "Kafka instance should have disk encryption enabled during deployment for data protection.",
		"zh": "Kafka 实例部署时启用了云盘加密，视为合规。Serverless 或非服务中的实例视为不适用。",
	},
	"reason": {
		"en": "Kafka instance does not have disk encryption enabled, which may expose data to security risks.",
		"zh": "Kafka 实例未启用云盘加密，可能导致数据面临安全风险。",
	},
	"recommendation": {
		"en": "Enable disk encryption by configuring KMSKeyId in DeployOption when deploying the Kafka instance.",
		"zh": "在部署 Kafka 实例时，通过在 DeployOption 中配置 KMSKeyId 来启用云盘加密。",
	},
	"resource_types": ["ALIYUN::KAFKA::Instance"],
}

# Check if the instance is serverless (not applicable)
is_serverless(resource) if {
	resource.Properties.PayType == "Serverless"
}

# Check if disk encryption is enabled via KMSKeyId in DeployOption
is_disk_encrypted(resource) if {
	resource.Properties.DeployOption.KMSKeyId != null
}

# Generate deny for non-compliant resources
# Skip serverless instances as they are not applicable
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::KAFKA::Instance")
	not is_serverless(resource)
	not is_disk_encrypted(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "DeployOption", "KMSKeyId"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
