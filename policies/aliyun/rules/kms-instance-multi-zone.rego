package infraguard.rules.aliyun.kms_instance_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:kms-instance-multi-zone",
	"name": {
		"en": "KMS Instance Multi-Zone Deployment",
		"zh": "使用多可用区的 KMS 实例",
	},
	"severity": "medium",
	"description": {
		"en": "KMS instances should be deployed across at least two availability zones for high availability and disaster recovery.",
		"zh": "使用多可用区的 KMS 实例，视为合规。",
	},
	"reason": {
		"en": "The KMS instance is not configured with multiple availability zones, which may affect availability.",
		"zh": "KMS 实例未配置多个可用区，可能影响可用性。",
	},
	"recommendation": {
		"en": "Configure at least two availability zones in the Connection.ZoneIds property to enable multi-zone deployment.",
		"zh": "在 Connection.ZoneIds 属性中配置至少两个可用区，以启用多可用区部署。",
	},
	"resource_types": ["ALIYUN::KMS::Instance"],
}

# Check if instance has multiple zones configured
has_multiple_zones(resource) if {
	helpers.has_property(resource, "Connection")
	connection := resource.Properties.Connection
	zone_ids := connection.ZoneIds
	count(zone_ids) >= 2
}

# Deny rule: KMS instances must be deployed in multiple zones
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::KMS::Instance")
	not has_multiple_zones(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Connection", "ZoneIds"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
