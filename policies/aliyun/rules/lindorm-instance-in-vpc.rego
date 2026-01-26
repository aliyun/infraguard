package infraguard.rules.aliyun.lindorm_instance_in_vpc

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "lindorm-instance-in-vpc",
	"name": {
		"en": "Lindorm in VPC Check",
		"zh": "Lindorm 实例强制 VPC 部署"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures Lindorm instances are deployed within a VPC.",
		"zh": "确保 Lindorm 实例部署在 VPC 内。"
	},
	"reason": {
		"en": "Deploying in a VPC provides better network isolation and security.",
		"zh": "在 VPC 中部署可提供更好的网络隔离和安全性。"
	},
	"recommendation": {
		"en": "Create Lindorm instances within a VPC.",
		"zh": "在 VPC 内创建 Lindorm 实例。"
	},
	"resource_types": ["ALIYUN::Lindorm::Instance"],
}

is_compliant(resource) if {
	vpc_id := helpers.get_property(resource, "VpcId", "")
	vpc_id != ""
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::Lindorm::Instance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "VpcId"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
