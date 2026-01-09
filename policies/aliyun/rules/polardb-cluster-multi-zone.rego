package infraguard.rules.aliyun.polardb_cluster_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:polardb-cluster-multi-zone",
	"name": {
		"en": "PolarDB Cluster Multi-Zone Deployment",
		"zh": "PolarDB 集群多可用区部署",
	},
	"severity": "medium",
	"description": {
		"en": "PolarDB clusters should be deployed across multiple availability zones for high availability.",
		"zh": "PolarDB 集群应部署在多个可用区。",
	},
	"reason": {
		"en": "The PolarDB cluster is not configured with a standby availability zone.",
		"zh": "PolarDB 集群未配置备用可用区。",
	},
	"recommendation": {
		"en": "Configure StandbyAZ to enable multi-zone deployment.",
		"zh": "配置 StandbyAZ 以启用多可用区部署。",
	},
	"resource_types": ["ALIYUN::POLARDB::DBCluster"],
}

# Check if cluster is multi-zone
is_multi_zone(resource) if {
	# Check if StandbyAZ is present and not empty
	object.get(resource.Properties, "StandbyAZ", "") != ""
}

# Deny rule
deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_multi_zone(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "StandbyAZ"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
