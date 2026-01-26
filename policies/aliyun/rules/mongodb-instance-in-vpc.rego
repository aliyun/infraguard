package infraguard.rules.aliyun.mongodb_instance_in_vpc

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "mongodb-instance-in-vpc",
	"name": {
		"en": "MongoDB Instance Uses VPC Network",
		"zh": "使用专有网络类型的 MongoDB 实例",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures MongoDB instances are deployed in a Virtual Private Cloud (VPC) network.",
		"zh": "确保 MongoDB 实例部署在专有网络（VPC）中。",
	},
	"reason": {
		"en": "VPC provides network isolation and better security compared to the classic network.",
		"zh": "与经典网络相比，VPC 提供网络隔离和更好的安全性。",
	},
	"recommendation": {
		"en": "Deploy the MongoDB instance in a VPC network.",
		"zh": "将 MongoDB 实例部署在专有网络中。",
	},
	"resource_types": ["ALIYUN::MONGODB::Instance"],
}

# Check if instance is in VPC
is_compliant(resource) if {
	vpc_id := helpers.get_property(resource, "VpcId", "")
	vpc_id != ""
}

is_compliant(resource) if {
	network_type := helpers.get_property(resource, "NetworkType", "")
	network_type == "VPC"
}

deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_compliant(resource)
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
