package infraguard.rules.aliyun.polardb_cluster_maintain_time_check

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:polardb-cluster-maintain-time-check",
	"name": {
		"en": "PolarDB Cluster Maintenance Window Check",
		"zh": "PolarDB 集群维护时间检测",
	},
	"severity": "low",
	"description": {
		"en": "Ensures that the PolarDB cluster has a maintenance window configured.",
		"zh": "确保 PolarDB 集群配置了维护时间段。",
	},
	"reason": {
		"en": "Configuring a maintenance window allows for planned maintenance during off-peak hours.",
		"zh": "配置维护时间段允许在非高峰时段进行计划内维护。",
	},
	"recommendation": {
		"en": "Configure a maintenance window for the PolarDB cluster.",
		"zh": "为 PolarDB 集群配置维护时间段。",
	},
	"resource_types": ["ALIYUN::POLARDB::DBCluster"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::POLARDB::DBCluster")
	not helpers.has_property(resource, "MaintainTime")
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "MaintainTime"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
