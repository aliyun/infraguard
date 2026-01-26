package infraguard.rules.aliyun.oss_zrs_enabled

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "oss-zrs-enabled",
	"name": {
		"en": "OSS Bucket Zone-Redundant Storage Enabled",
		"zh": "OSS 桶启用同城冗余存储",
	},
	"severity": "medium",
	"description": {
		"en": "OSS buckets should use zone-redundant storage (ZRS) for high availability and data durability.",
		"zh": "OSS 桶应使用同城冗余存储（ZRS）以实现高可用性和数据持久性。",
	},
	"reason": {
		"en": "The OSS bucket does not have zone-redundant storage enabled, which may affect data availability.",
		"zh": "OSS 桶未启用同城冗余存储，可能影响数据可用性。",
	},
	"recommendation": {
		"en": "Enable zone-redundant storage by setting RedundancyType to 'ZRS' when creating the bucket.",
		"zh": "在创建桶时通过将 RedundancyType 设置为'ZRS'来启用同城冗余存储。",
	},
	"resource_types": ["ALIYUN::OSS::Bucket"],
}

# Check if bucket has ZRS enabled
has_zrs_enabled(resource) if {
	redundancy_type := helpers.get_property(resource, "RedundancyType", "LRS")
	redundancy_type == "ZRS"
}

# Deny rule: OSS buckets should have ZRS enabled
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::OSS::Bucket")
	not has_zrs_enabled(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "RedundancyType"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
