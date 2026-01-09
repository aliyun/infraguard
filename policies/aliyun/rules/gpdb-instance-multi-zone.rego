package infraguard.rules.aliyun.gpdb_instance_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:gpdb-instance-multi-zone",
	"name": {
		"en": "GPDB Instance Multi-Zone Deployment",
		"zh": "使用多可用区的云原生数据仓库 AnalyticDB 实例",
	},
	"severity": "medium",
	"description": {
		"en": "GPDB instances should be deployed with a standby zone for high availability.",
		"zh": "使用多可用区的云原生数据仓库 AnalyticDB 实例，视为合规。",
	},
	"reason": {
		"en": "The GPDB instance does not have a standby zone configured, which may affect availability.",
		"zh": "GPDB 实例未配置备用可用区，可能影响可用性。",
	},
	"recommendation": {
		"en": "Configure a standby zone by setting the StandbyZoneId property to enable multi-zone deployment.",
		"zh": "通过设置 StandbyZoneId 属性配置备用可用区，以启用多可用区部署。",
	},
	"resource_types": ["ALIYUN::GPDB::DBInstance"],
}

# Check if instance has standby zone
has_standby_zone(resource) if {
	helpers.has_property(resource, "StandbyZoneId")
	standby_zone := resource.Properties.StandbyZoneId
	standby_zone != ""
}

# Deny rule: GPDB instances should have standby zone
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::GPDB::DBInstance")
	not has_standby_zone(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "StandbyZoneId"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
