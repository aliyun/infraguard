package infraguard.rules.aliyun.polardb_cluster_delete_protection_enabled

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "rule:aliyun:polardb-cluster-delete-protection-enabled",
	"name": {
		"en": "PolarDB Cluster Deletion Protection Enabled",
		"zh": "PolarDB 集群开启删除保护",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that PolarDB clusters have deletion protection enabled.",
		"zh": "确保 PolarDB 集群开启了删除保护。",
	},
	"reason": {
		"en": "If deletion protection is not enabled, the PolarDB cluster may be released accidentally, causing data loss.",
		"zh": "如果未开启删除保护，PolarDB 集群可能会被意外释放，导致数据丢失。",
	},
	"recommendation": {
		"en": "Enable deletion protection for the PolarDB cluster.",
		"zh": "为 PolarDB 集群开启删除保护功能。",
	},
	"resource_types": ["ALIYUN::POLARDB::DBCluster"],
}

is_compliant(resource) if {
	helpers.is_true(helpers.get_property(resource, "DeletionProtection", false))
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::POLARDB::DBCluster")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "DeletionProtection"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
