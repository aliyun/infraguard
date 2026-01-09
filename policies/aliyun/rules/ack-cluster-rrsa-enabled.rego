package infraguard.rules.aliyun.ack_cluster_rrsa_enabled

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:ack-cluster-rrsa-enabled",
	"name": {
		"en": "ACK Cluster RRSA Enabled",
		"zh": "ACK 集群开启 RRSA",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that the RAM Roles for Service Accounts (RRSA) feature is enabled for the ACK cluster.",
		"zh": "确保 ACK 集群开启了 RAM 角色注入(RRSA)功能。",
	},
	"reason": {
		"en": "RRSA allows pods to assume RAM roles, providing a more secure and fine-grained way to manage permissions.",
		"zh": "RRSA 允许 Pod 扮演 RAM 角色，提供更安全、更细粒度的权限管理方式。",
	},
	"recommendation": {
		"en": "Enable RRSA for the ACK cluster.",
		"zh": "为 ACK 集群开启 RRSA 功能。",
	},
	"resource_types": ["ALIYUN::CS::ManagedKubernetesCluster", "ALIYUN::CS::AnyCluster"],
}

deny contains result if {
	some name, resource in helpers.resources_by_types(["ALIYUN::CS::ManagedKubernetesCluster", "ALIYUN::CS::AnyCluster"])
	rrsa_config := helpers.get_property(resource, "RrsaConfig", {})
	enabled := rrsa_config.Enabled
	not helpers.is_true(enabled)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "RrsaConfig", "Enabled"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
