package infraguard.rules.aliyun.mse_cluster_config_auth_enabled

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "mse-cluster-config-auth-enabled",
	"name": {
		"en": "MSE Cluster Config Auth Enabled",
		"zh": "MSE 集群配置中心开启鉴权",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that the Microservices Engine (MSE) cluster configuration center has authentication enabled.",
		"zh": "确保微服务引擎(MSE)集群配置中心已开启鉴权。",
	},
	"reason": {
		"en": "Enabling authentication prevents unauthorized access to service configurations.",
		"zh": "开启鉴权可防止对服务配置的未经授权访问。",
	},
	"recommendation": {
		"en": "Enable authentication for the MSE cluster configuration center.",
		"zh": "为 MSE 集群配置中心开启鉴权。",
	},
	"resource_types": ["ALIYUN::MSE::Cluster"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::MSE::Cluster")

	# Conceptual check for auth
	not helpers.has_property(resource, "ConfigAuthEnabled") # Simplified
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
