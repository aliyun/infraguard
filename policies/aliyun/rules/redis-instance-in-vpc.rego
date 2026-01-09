package infraguard.rules.aliyun.redis_instance_in_vpc

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "rule:aliyun:redis-instance-in-vpc",
	"name": {
		"en": "Redis Instance in VPC",
		"zh": "使用专有网络类型的 Redis 实例"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures Redis instance is deployed in a VPC.",
		"zh": "确保 Redis 实例部署在专有网络中。"
	},
	"reason": {
		"en": "VPC provides better network isolation and security.",
		"zh": "VPC 提供更好的网络隔离和安全性。"
	},
	"recommendation": {
		"en": "Deploy Redis instance in a VPC.",
		"zh": "将 Redis 部署在专有网络中。"
	},
	"resource_types": ["ALIYUN::REDIS::Instance"],
}

is_compliant(resource) if {
	vpc_id := helpers.get_property(resource, "VpcId", "")
	vpc_id != ""
}

is_compliant(resource) if {
	vswitch_id := helpers.get_property(resource, "VSwitchId", "")
	vswitch_id != ""
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::REDIS::Instance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "VpcId"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
