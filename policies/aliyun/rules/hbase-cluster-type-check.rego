package infraguard.rules.aliyun.hbase_cluster_type_check

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:hbase-cluster-type-check",
	"name": {
		"en": "HBase Cluster Type Check",
		"zh": "HBase 集群实例类型检测",
	},
	"severity": "low",
	"description": {
		"en": "Ensures that the HBase cluster is of a specified or recommended type.",
		"zh": "确保 HBase 集群是指定的或推荐的类型。",
	},
	"reason": {
		"en": "Using the correct cluster type ensures optimal performance and support for your workload.",
		"zh": "使用正确的集群类型可确保您的工作负载获得最佳性能和支持。",
	},
	"recommendation": {
		"en": "Select a recommended HBase cluster type.",
		"zh": "选择推荐的 HBase 集群类型。",
	},
	"resource_types": ["ALIYUN::HBase::Cluster"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::HBase::Cluster")
	helpers.get_property(resource, "ClusterType", "") == "deprecated"
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "ClusterType"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
