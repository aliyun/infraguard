package infraguard.rules.aliyun.adb_cluster_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "adb-cluster-multi-zone",
	"name": {
		"en": "ADB Cluster Multi-Zone Deployment",
		"zh": "ADB 集群部署模式为多可用区",
	},
	"severity": "medium",
	"description": {
		"en": "The ADB cluster should be deployed in multi-zone mode.",
		"zh": "ADB 集群为多可用区部署模式，视为合规。",
	},
	"reason": {
		"en": "The ADB cluster is not configured with a secondary zone, indicating it is single-zone.",
		"zh": "ADB 集群未配置备可用区，表明其为单可用区部署。",
	},
	"recommendation": {
		"en": "Configure the SecondaryZoneId to enable multi-zone deployment.",
		"zh": "配置 SecondaryZoneId 以启用多可用区部署。",
	},
	"resource_types": ["ALIYUN::ADBLake::DBCluster"],
}

# Check if ADB is multi-zone
is_multi_zone(resource) if {
	# Check if SecondaryZoneId is present
	object.get(resource.Properties, "SecondaryZoneId", "") != ""
}

# Deny rule
deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_multi_zone(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SecondaryZoneId"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
