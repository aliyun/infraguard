package infraguard.rules.aliyun.ack_cluster_encryption_enabled

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "rule:aliyun:ack-cluster-encryption-enabled",
	"name": {
		"en": "ACK Cluster Secret Encryption Enabled",
		"zh": "ACK 集群配置 Secret 的落盘加密",
	},
	"severity": "medium",
	"description": {
		"en": "ACK Pro clusters should have Secret encryption at rest enabled using KMS.",
		"zh": "ACK 集群配置 Secret 的落盘加密，视为合规。非专业托管版集群视为不适用。",
	},
	"reason": {
		"en": "The ACK Pro cluster does not have Secret encryption at rest enabled.",
		"zh": "ACK 专业版集群未开启 Secret 落盘加密。",
	},
	"recommendation": {
		"en": "Enable Secret encryption by specifying EncryptionProviderKey.",
		"zh": "通过指定 EncryptionProviderKey 开启 Secret 加密。",
	},
	"resource_types": ["ALIYUN::CS::ManagedKubernetesCluster"],
}

# Check if cluster is ACK Pro
is_ack_pro(resource) if {
	helpers.get_property(resource, "ClusterSpec", "") == "ack.pro.small"
}

# Check if encryption is enabled
is_encryption_enabled(resource) if {
	helpers.has_property(resource, "EncryptionProviderKey")
}

deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	is_ack_pro(resource)
	not is_encryption_enabled(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "EncryptionProviderKey"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
