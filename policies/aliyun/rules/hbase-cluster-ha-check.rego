package infraguard.rules.aliyun.hbase_cluster_ha_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rule:aliyun:hbase-cluster-ha-check",
	"name": {
		"en": "HBase Cluster HA Enabled",
		"zh": "HBase 集群强制开启高可用"
	},
	"severity": "high",
	"description": {
		"en": "Ensures HBase clusters are configured for High Availability (HA).",
		"zh": "确保 HBase 集群配置为高可用（HA）模式。"
	},
	"reason": {
		"en": "Non-HA clusters are single points of failure and may lead to service downtime.",
		"zh": "非高可用集群存在单点故障风险，可能导致服务中断。"
	},
	"recommendation": {
		"en": "Ensure NodeCount is sufficient for HA (at least 2 for disk-based, 3 for local disks).",
		"zh": "确保节点数量满足高可用要求（磁盘型至少 2 个，本地盘型至少 3 个）。"
	},
	"resource_types": ["ALIYUN::HBase::Cluster"],
}

is_compliant(resource) if {
	count := helpers.get_property(resource, "NodeCount", 1)
	count >= 2
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::HBase::Cluster")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "NodeCount"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
