package infraguard.rules.aliyun.mongodb_min_maxiops_limit

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "rule:aliyun:mongodb-min-maxiops-limit",
	"name": {
		"en": "MongoDB Meets Minimum IOPS Requirements",
		"zh": "MongoDB 实例满足指定读写次数要求",
	},
	"severity": "high",
	"description": {
		"en": "Ensures MongoDB instances provide at least the minimum required IOPS.",
		"zh": "确保 MongoDB 实例提供至少所需的最少 IOPS。",
	},
	"reason": {
		"en": "Insufficient IOPS may cause performance issues under load.",
		"zh": "IOPS 不足可能在负载下导致性能问题。",
	},
	"recommendation": {
		"en": "Select an instance class or storage that provides sufficient IOPS.",
		"zh": "选择提供足够 IOPS 的实例规格或存储。",
	},
	"resource_types": ["ALIYUN::MONGODB::Instance"],
}

# Default minimum IOPS
default_min_iops := 1000

# Get min IOPS from parameter or use default
get_min_iops := iops if {
	iops := input.parameters.minIOPS
	is_number(iops)
} else := default_min_iops

# Get max IOPS for the instance
get_max_iops(resource) := iops if {
	iops := helpers.get_property(resource, "MaxIOPS", 0)
	is_number(iops)
}

# Check if instance meets IOPS requirements
is_compliant(resource) if {
	max_iops := get_max_iops(resource)
	min_required := get_min_iops()
	max_iops >= min_required
}

# Also check based on instance class and storage
is_compliant(resource) if {
	instance_class := helpers.get_property(resource, "DBInstanceClass", "")
	instance_storage := helpers.get_property(resource, "DBInstanceStorage", 0)
	storage_type := helpers.get_property(resource, "StorageType", "cloud_ssd")

	instance_storage >= 100
	contains(lower(storage_type), "ssd")
}

deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "MaxIOPS"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
