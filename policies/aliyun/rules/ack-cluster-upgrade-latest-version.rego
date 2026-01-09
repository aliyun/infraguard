package infraguard.rules.aliyun.ack_cluster_upgrade_latest_version

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:ack-cluster-upgrade-latest-version",
	"name": {
		"en": "ACK Cluster Upgraded to Latest Version",
		"zh": "ACK 集群已升级至最新版本",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that the ACK cluster is running the latest available version.",
		"zh": "确保 ACK 集群运行的是最新的可用版本。",
	},
	"reason": {
		"en": "Running the latest version ensures that you have the latest security patches and features.",
		"zh": "运行最新版本可确保您获得最新的安全补丁和功能。",
	},
	"recommendation": {
		"en": "Upgrade the ACK cluster to the latest available version.",
		"zh": "将 ACK 集群升级到最新的可用版本。",
	},
	"resource_types": ["ALIYUN::CS::ManagedKubernetesCluster", "ALIYUN::CS::AnyCluster"],
}

deny contains result if {
	some name, resource in helpers.resources_by_types(["ALIYUN::CS::ManagedKubernetesCluster", "ALIYUN::CS::AnyCluster"])

	# Conceptual check for version
	helpers.has_property(resource, "ClusterVersion")
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "ClusterVersion"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
