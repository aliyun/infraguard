package infraguard.rules.aliyun.elasticsearch_instance_enabled_node_config_disk_encryption

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rule:aliyun:elasticsearch-instance-enabled-node-config-disk-encryption",
	"name": {
		"en": "ES Node Config Disk Encryption",
		"zh": "ES 弹性节点磁盘加密核查"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures Elasticsearch elastic node configurations have disk encryption enabled.",
		"zh": "确保 Elasticsearch 弹性节点配置开启了磁盘加密。"
	},
	"reason": {
		"en": "Elastic nodes can store sensitive transient data.",
		"zh": "弹性节点可能存储敏感的临时数据。"
	},
	"recommendation": {
		"en": "Enable disk encryption for all node configurations in the ES instance.",
		"zh": "为 Elasticsearch 实例中的所有节点配置开启磁盘加密。"
	},
	"resource_types": ["ALIYUN::ElasticSearch::Instance"],
}

is_compliant(resource) if {
	# DataNode disk encryption check
	node := helpers.get_property(resource, "DataNode", {})
	helpers.is_true(object.get(node, "DiskEncryption", false))
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ElasticSearch::Instance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "DataNode", "DiskEncryption"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
