package infraguard.rules.aliyun.mongodb_instance_class_not_shared

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "mongodb-instance-class-not-shared",
	"name": {
		"en": "MongoDB Instance Uses Dedicated Class",
		"zh": "MongoDB 使用独享型或专属型规格实例",
	},
	"severity": "high",
	"description": {
		"en": "Ensures MongoDB instances use dedicated or exclusive instance classes, not shared instances.",
		"zh": "确保 MongoDB 实例使用独享型或专属型规格实例，而非共享型实例。",
	},
	"reason": {
		"en": "Shared instance classes may have resource contention issues, affecting database performance and stability.",
		"zh": "共享型实例规格可能存在资源争用问题，影响数据库性能和稳定性。",
	},
	"recommendation": {
		"en": "Use dedicated or exclusive instance classes for MongoDB instances.",
		"zh": "为 MongoDB 实例使用独享型或专属型规格实例。",
	},
	"resource_types": ["ALIYUN::MONGODB::Instance"],
}

# Shared instance class patterns (these are typically shared types)
shared_classes := {
	"dds.mongo.sharding",
	"dds.mongo.logic",
	"dds.mongo.shared",
}

# Check if instance class is not shared
is_compliant(resource) if {
	instance_class := helpers.get_property(resource, "DBInstanceClass", "")
	not contains_shared_class(lower(instance_class))
}

contains_shared_class(instance_class) if {
	some shared_class in shared_classes
	contains(instance_class, shared_class)
}

deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "DBInstanceClass"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
