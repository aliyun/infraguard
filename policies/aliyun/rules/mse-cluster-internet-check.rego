package infraguard.rules.aliyun.mse_cluster_internet_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "mse-cluster-internet-check",
	"name": {
		"en": "MSE Cluster Has No Public Internet Access",
		"zh": "MSE 集群公网检测",
	},
	"severity": "high",
	"description": {
		"en": "Ensures that MSE clusters do not have public internet access enabled.",
		"zh": "确保 MSE 集群未开放公网访问。",
	},
	"reason": {
		"en": "Public internet access increases the attack surface and security risks for the cluster.",
		"zh": "公网访问增加了集群的攻击面和安全风险。",
	},
	"recommendation": {
		"en": "Configure the MSE cluster to use private network access only.",
		"zh": "配置 MSE 集群仅使用内网访问。",
	},
	"resource_types": ["ALIYUN::MSE::Cluster"],
}

# Check if cluster has public internet access
has_public_internet(resource) if {
	net_type := helpers.get_property(resource, "NetType", "privatenet")
	net_type == "pubnet"
}

has_public_internet(resource) if {
	pub_network_flow := helpers.get_property(resource, "PubNetworkFlow", 0)
	pub_network_flow > 0
}

has_public_internet(resource) if {
	connection_type := helpers.get_property(resource, "ConnectionType", "")
	connection_type == "single_eni"
	eip_enabled := helpers.get_property(resource, "EipEnabled", false)
	helpers.is_true(eip_enabled)
}

is_compliant(resource) if {
	not has_public_internet(resource)
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::MSE::Cluster")
	has_public_internet(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "NetType"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
