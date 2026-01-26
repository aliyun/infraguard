package infraguard.rules.aliyun.hbase_cluster_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "hbase-cluster-multi-zone",
	"name": {
		"en": "HBase Cluster Multi-Zone Deployment",
		"zh": "使用多可用区的 HBase 集群",
	},
	"severity": "medium",
	"description": {
		"en": "HBase clusters should be deployed in cluster mode with at least 2 nodes for high availability.",
		"zh": "使用多可用区的 HBase 集群，视为合规。",
	},
	"reason": {
		"en": "The HBase cluster is deployed in single-node mode, which does not provide high availability.",
		"zh": "HBase 集群部署在单节点模式，不提供高可用性。",
	},
	"recommendation": {
		"en": "Deploy HBase cluster in cluster mode by setting NodeCount to at least 2 for high availability.",
		"zh": "通过将 NodeCount 设置为至少 2 来部署 HBase 集群的集群模式，以实现高可用性。",
	},
	"resource_types": ["ALIYUN::HBase::Cluster"],
}

# Check if cluster is in cluster mode (at least 2 nodes)
is_cluster_mode(resource) if {
	node_count := resource.Properties.NodeCount
	node_count >= 2
}

# Deny rule: HBase clusters should be in cluster mode
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::HBase::Cluster")
	not is_cluster_mode(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "NodeCount"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
