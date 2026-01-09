package infraguard.rules.aliyun.rds_instances_in_vpc

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:rds-instances-in-vpc",
	"name": {
		"en": "RDS Instance in VPC",
		"zh": "RDS 实例在 VPC 内",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that the RDS instance is deployed within a VPC.",
		"zh": "确保 RDS 实例部署在 VPC 内。",
	},
	"reason": {
		"en": "Deploying RDS in a VPC provides better network isolation and security.",
		"zh": "在 VPC 中部署 RDS 可提供更好的网络隔离和安全性。",
	},
	"recommendation": {
		"en": "Deploy the RDS instance within a VPC.",
		"zh": "将 RDS 实例部署在 VPC 内。",
	},
	"resource_types": ["ALIYUN::RDS::DBInstance"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::RDS::DBInstance")
	not helpers.has_property(resource, "VPCId")
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "VPCId"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
