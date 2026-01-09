package infraguard.rules.aliyun.mse_cluster_multi_availability_area_architecture_check

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:mse-cluster-multi-availability-area-architecture-check",
	"name": {
		"en": "MSE Cluster High-Availability Configuration",
		"zh": "使用高可用版本的 MSE 注册配置中心",
	},
	"severity": "medium",
	"description": {
		"en": "MSE clusters should use the Professional Edition with at least 3 instances (odd number) for high availability.",
		"zh": "使用高可用版本的 MSE 注册配置中心，视为合规。",
	},
	"reason": {
		"en": "The MSE cluster does not meet high-availability requirements (Professional Edition requires InstanceCount >= 3 and odd number).",
		"zh": "MSE 集群不满足高可用性要求（专业版要求 InstanceCount >= 3 且为奇数）。",
	},
	"recommendation": {
		"en": "Use Professional Edition (MseVersion: mse_pro) and set InstanceCount to at least 3 (odd number) for high availability.",
		"zh": "使用专业版（MseVersion: mse_pro）并将 InstanceCount 设置为至少 3（奇数）以实现高可用性。",
	},
	"resource_types": ["ALIYUN::MSE::Cluster"],
}

# Check if cluster is Professional Edition
is_professional_edition(resource) if {
	helpers.has_property(resource, "MseVersion")
	mse_version := resource.Properties.MseVersion
	mse_version == "mse_pro"
}

# Check if instance count meets HA requirements (>= 3 and odd)
has_ha_instance_count(resource) if {
	instance_count := resource.Properties.InstanceCount
	instance_count >= 3
	instance_count % 2 == 1
}

# Check if cluster is high availability
is_high_availability(resource) if {
	is_professional_edition(resource)
	has_ha_instance_count(resource)
}

# Deny rule: MSE clusters should be high availability
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::MSE::Cluster")
	not is_high_availability(resource)
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
