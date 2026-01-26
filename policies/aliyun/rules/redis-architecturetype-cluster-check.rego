package infraguard.rules.aliyun.redis_architecturetype_cluster_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "redis-architecturetype-cluster-check",
	"name": {
		"en": "Redis Architecture Type Cluster Check",
		"zh": "使用集群版的 Redis 实例"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures Redis instance uses cluster architecture type.",
		"zh": "确保 Redis 实例的架构类型为集群版。"
	},
	"reason": {
		"en": "Cluster architecture provides better scalability and high availability.",
		"zh": "集群架构提供更好的可扩展性和高可用性。"
	},
	"recommendation": {
		"en": "Use cluster architecture for Redis instance.",
		"zh": "为 Redis 实例使用集群架构。"
	},
	"resource_types": ["ALIYUN::REDIS::Instance"],
}

is_compliant(resource) if {
	instance_class := helpers.get_property(resource, "InstanceClass", "")
	contains(instance_class, "cluster")
}

is_compliant(resource) if {
	shard_count := helpers.get_property(resource, "ShardCount", 1)
	shard_count >= 2
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::REDIS::Instance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "ShardCount"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
