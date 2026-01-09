package infraguard.rules.aliyun.mongodb_instance_multi_node

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "rule:aliyun:mongodb-instance-multi-node",
	"name": {
		"en": "MongoDB Instance Uses Multiple Nodes",
		"zh": "使用多节点的 MongoDB 实例",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures MongoDB instances are deployed with multiple nodes for high availability.",
		"zh": "确保 MongoDB 实例部署了多个节点以实现高可用性。",
	},
	"reason": {
		"en": "Single-node instances have no redundancy and are at risk of data loss or service interruption.",
		"zh": "单节点实例没有冗余，存在数据丢失或服务中断的风险。",
	},
	"recommendation": {
		"en": "Deploy MongoDB instances with multiple replica set nodes.",
		"zh": "部署具有多个副本集节点的 MongoDB 实例。",
	},
	"resource_types": ["ALIYUN::MONGODB::Instance"],
}

# Check if instance has multiple nodes
is_compliant(resource) if {
	replication_factor := helpers.get_property(resource, "ReplicationFactor", 0)
	replication_factor >= 3
}

is_compliant(resource) if {
	instance_class := helpers.get_property(resource, "DBInstanceClass", "")

	# Check if it's a replica set class (typically contains 'replica' or has specific patterns)
	contains(lower(instance_class), "replica")
}

is_compliant(resource) if {
	instance_class := helpers.get_property(resource, "DBInstanceClass", "")
	contains(lower(instance_class), "sharding")
}

deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "ReplicationFactor"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
