package infraguard.rules.aliyun.polardb_revision_version_used_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "rule:aliyun:polardb-revision-version-used-check",
	"name": {
		"en": "PolarDB Revision Version Used Check",
		"zh": "使用稳定内核版本的 PolarDB 集群"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures PolarDB cluster is using a stable kernel revision version.",
		"zh": "确保 PolarDB 集群使用稳定内核版本。"
	},
	"reason": {
		"en": "Using stable kernel version ensures better reliability and security.",
		"zh": "使用稳定内核版本确保更好的可靠性和安全性。"
	},
	"recommendation": {
		"en": "Use stable kernel version for the PolarDB cluster.",
		"zh": "为 PolarDB 集群使用稳定内核版本。"
	},
	"resource_types": ["ALIYUN::POLARDB::DBCluster"],
}

is_compliant(resource) if {
	db_version := helpers.get_property(resource, "DBVersion", "")
	db_version != ""
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::POLARDB::DBCluster")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "DBVersion"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
