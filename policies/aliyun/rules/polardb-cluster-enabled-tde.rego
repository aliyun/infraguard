package infraguard.rules.aliyun.polardb_cluster_enabled_tde

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "polardb-cluster-enabled-tde",
	"name": {
		"en": "PolarDB Cluster TDE Enabled",
		"zh": "PolarDB 集群开启 TDE"
	},
	"severity": "high",
	"description": {
		"en": "Ensures PolarDB clusters have Transparent Data Encryption (TDE) enabled.",
		"zh": "确保 PolarDB 集群开启了透明数据加密（TDE）。"
	},
	"reason": {
		"en": "TDE provides data-at-rest encryption for sensitive data stored in the database.",
		"zh": "TDE 为存储在数据库中的敏感数据提供静态数据加密。"
	},
	"recommendation": {
		"en": "Enable TDE for the PolarDB cluster.",
		"zh": "为 PolarDB 集群开启 TDE。"
	},
	"resource_types": ["ALIYUN::POLARDB::DBCluster"],
}

is_compliant(resource) if {
	helpers.is_true(helpers.get_property(resource, "TDEStatus", false))
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::POLARDB::DBCluster")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "TDEStatus"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
