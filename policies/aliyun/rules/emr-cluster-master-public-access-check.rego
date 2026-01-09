package infraguard.rules.aliyun.emr_cluster_master_public_access_check

import rego.v1

import data.infraguard.helpers

# Rule metadata with i18n support
rule_meta := {
	"id": "rule:aliyun:emr-cluster-master-public-access-check",
	"name": {
		"en": "EMR Cluster Master Node Public Access Check",
		"zh": "EMR 集群 Master 节点公网开启检测",
	},
	"severity": "medium",
	"description": {
		"en": "EMR on ECS cluster master nodes should not have public IP enabled.",
		"zh": "EMR on ECS 集群 Master 节点公网不开启，视为合规。",
	},
	"reason": {
		"en": "EMR master nodes with public IP enabled may be exposed to the internet, increasing security risks.",
		"zh": "EMR Master 节点开启公网 IP 可能会暴露在互联网中，增加安全风险。",
	},
	"recommendation": {
		"en": "Set 'IsOpenPublicIp' to false for the EMR cluster and use a NAT gateway or bastion host for access.",
		"zh": "将 EMR 集群的'IsOpenPublicIp'属性设置为 false，并使用 NAT 网关或堡垒机进行访问。",
	},
	"resource_types": ["ALIYUN::EMR::Cluster"],
}

# Deny if IsOpenPublicIp is true
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::EMR::Cluster")
	resource.Properties.IsOpenPublicIp == true

	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "IsOpenPublicIp"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
