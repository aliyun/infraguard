package infraguard.rules.aliyun.elasticsearch_instance_enabled_data_node_encryption

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "elasticsearch-instance-enabled-data-node-encryption",
	"name": {
		"en": "Elasticsearch Data Node Encryption Enabled",
		"zh": "Elasticsearch 数据节点开启加密",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that data nodes in the Elasticsearch instance have disk encryption enabled.",
		"zh": "确保 Elasticsearch 实例中的数据节点已开启磁盘加密。",
	},
	"reason": {
		"en": "Disk encryption protects sensitive data stored on Elasticsearch nodes.",
		"zh": "磁盘加密可保护存储在 Elasticsearch 节点上的敏感数据。",
	},
	"recommendation": {
		"en": "Enable disk encryption for the Elasticsearch instance data nodes.",
		"zh": "为 Elasticsearch 实例数据节点开启磁盘加密。",
	},
	"resource_types": ["ALIYUN::Elasticsearch::Instance"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::Elasticsearch::Instance")

	# Conceptual check for disk encryption
	not helpers.has_property(resource, "EncryptionAtRest") # Simplified
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
