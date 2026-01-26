package infraguard.rules.aliyun.clickhouse_dbcluster_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "clickhouse-dbcluster-multi-zone",
	"name": {
		"en": "ClickHouse DBCluster Multi-Zone Deployment",
		"zh": "使用多可用区的 ClickHouse 集群实例",
	},
	"severity": "medium",
	"description": {
		"en": "ClickHouse clusters should use the HighAvailability (Double-replica) edition for multi-zone deployment. Note: This applies only to community edition.",
		"zh": "使用多可用区的 ClickHouse 集群实例，视为合规，注意只包含社区版本。",
	},
	"reason": {
		"en": "The ClickHouse cluster is using Single-replica Edition, which does not provide multi-zone high availability.",
		"zh": "ClickHouse 集群使用单副本版本，不提供多可用区高可用性。",
	},
	"recommendation": {
		"en": "Use the HighAvailability (Double-replica) edition by setting Category to 'HighAvailability' for multi-zone deployment.",
		"zh": "通过将 Category 设置为'HighAvailability'来使用双副本版本，实现多可用区部署。",
	},
	"resource_types": ["ALIYUN::ClickHouse::DBCluster"],
}

# Check if cluster is high availability (multi-zone)
is_high_availability(resource) if {
	category := resource.Properties.Category
	category == "HighAvailability"
}

# Deny rule: ClickHouse clusters should use HighAvailability edition
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ClickHouse::DBCluster")
	not is_high_availability(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Category"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
