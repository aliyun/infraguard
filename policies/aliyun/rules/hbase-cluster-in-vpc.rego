package infraguard.rules.aliyun.hbase_cluster_in_vpc

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "hbase-cluster-in-vpc",
	"name": {
		"en": "HBase Cluster in VPC",
		"zh": "HBase 集群在 VPC 内",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that the HBase cluster is deployed within a VPC.",
		"zh": "确保 HBase 集群部署在 VPC 内。",
	},
	"reason": {
		"en": "Deploying HBase in a VPC provides better network isolation and security.",
		"zh": "在 VPC 中部署 HBase 可提供更好的网络隔离和安全性。",
	},
	"recommendation": {
		"en": "Deploy the HBase cluster within a VPC.",
		"zh": "将 HBase 集群部署在 VPC 内。",
	},
	"resource_types": ["ALIYUN::HBase::Cluster"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::HBase::Cluster")
	not helpers.has_property(resource, "VpcId")
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "VpcId"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
