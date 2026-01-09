package infraguard.rules.aliyun.mongodb_instance_encryption_byok_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "rule:aliyun:mongodb-instance-encryption-byok-check",
	"name": {
		"en": "MongoDB Instance Uses Custom Key for TDE",
		"zh": "使用自定义密钥为 MongoDB 设置透明数据加密 TDE",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures MongoDB instances use custom KMS keys for Transparent Data Encryption (TDE).",
		"zh": "确保 MongoDB 实例使用自定义 KMS 密钥进行透明数据加密（TDE）。",
	},
	"reason": {
		"en": "Using customer-managed keys for TDE provides better control over encryption and enhances data security.",
		"zh": "使用客户管理密钥进行 TDE 可以更好地控制加密并增强数据安全性。",
	},
	"recommendation": {
		"en": "Enable TDE with a custom KMS key for the MongoDB instance.",
		"zh": "为 MongoDB 实例启用 TDE 并使用自定义 KMS 密钥。",
	},
	"resource_types": ["ALIYUN::MONGODB::Instance"],
}

# Check if instance is Serverless type (not applicable)
is_serverless(resource) if {
	tags := helpers.get_property(resource, "Tags", [])
	some tag in tags
	tag.Key == "InstanceType"
	tag.Value == "Serverless"
}

is_serverless(resource) if {
	instance_class := helpers.get_property(resource, "DBInstanceClass", "")
	contains(lower(instance_class), "serverless")
}

# Check if TDE is enabled with custom key
is_compliant(resource) if {
	not is_serverless(resource)
	tde_enabled := helpers.get_property(resource, "TDEStatus", false)
	tde_enabled == true
	kms_key_id := helpers.get_property(resource, "EncryptionKey", "")
	kms_key_id != ""
}

deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_serverless(resource)
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "TDEStatus"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
