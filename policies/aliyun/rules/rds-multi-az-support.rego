package infraguard.rules.aliyun.rds_multi_az_support

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:rds-multi-az-support",
	"name": {
		"en": "RDS Instance Multi-AZ Deployment",
		"zh": "RDS 实例多可用区部署",
	},
	"severity": "medium",
	"description": {
		"en": "RDS instances should be deployed in multi-AZ configuration for high availability and automatic failover.",
		"zh": "RDS 实例应部署在多可用区配置中，以实现高可用性和自动故障转移。",
	},
	"reason": {
		"en": "The RDS instance is not deployed in multi-AZ configuration, which may affect availability during zone failures.",
		"zh": "RDS 实例未部署在多可用区配置中，在可用区故障时可能影响可用性。",
	},
	"recommendation": {
		"en": "Enable multi-AZ deployment by setting MultiAZ to true when creating the instance.",
		"zh": "在创建实例时通过将 MultiAZ 设置为 true 来启用多可用区部署。",
	},
	"resource_types": ["ALIYUN::RDS::DBInstance"],
}

# Check if instance has multi-AZ enabled
has_multi_az_enabled(resource) if {
	multi_az := helpers.get_property(resource, "MultiAZ", false)
	multi_az == true
}

# Deny rule: RDS instances should have multi-AZ enabled
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::RDS::DBInstance")
	not has_multi_az_enabled(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "MultiAZ"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
