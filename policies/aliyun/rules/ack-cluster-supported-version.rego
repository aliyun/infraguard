package infraguard.rules.aliyun.ack_cluster_supported_version

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "ack-cluster-supported-version",
	"name": {
		"en": "ACK Cluster Supported Version",
		"zh": "ACK 集群版本支持检测",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that the ACK cluster is running a supported version.",
		"zh": "确保 ACK 集群运行的是受支持的版本。",
	},
	"reason": {
		"en": "Running an unsupported version may lead to security vulnerabilities and lack of support.",
		"zh": "运行不受支持的版本可能导致安全漏洞和缺乏技术支持。",
	},
	"recommendation": {
		"en": "Upgrade the ACK cluster to a supported version.",
		"zh": "将 ACK 集群升级到受支持的版本。",
	},
	"resource_types": ["ALIYUN::CS::ManagedKubernetesCluster", "ALIYUN::CS::AnyCluster"],
}

deny contains result if {
	some name, resource in helpers.resources_by_types(["ALIYUN::CS::ManagedKubernetesCluster", "ALIYUN::CS::AnyCluster"])

	# Conceptual check - any cluster with a version is potentially unsupported
	helpers.has_property(resource, "KubernetesVersion")
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "KubernetesVersion"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
