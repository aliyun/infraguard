package infraguard.rules.aliyun.fc_service_vpc_binding

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:fc-service-vpc-binding",
	"name": {
		"en": "FC Service VPC Binding Enabled",
		"zh": "FC 服务绑定 VPC",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that the Function Compute service is configured to access resources within a VPC.",
		"zh": "确保函数计算服务已配置为访问 VPC 内的资源。",
	},
	"reason": {
		"en": "Binding a VPC to an FC service allows functions to securely access internal resources like databases and internal APIs.",
		"zh": "为 FC 服务绑定 VPC 允许函数安全地访问内网资源，如数据库和内部 API。",
	},
	"recommendation": {
		"en": "Configure VPC access for the Function Compute service.",
		"zh": "为函数计算服务配置 VPC 访问。",
	},
	"resource_types": ["ALIYUN::FC::Service"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::FC::Service")
	not helpers.has_property(resource, "VpcConfig")
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "VpcConfig"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
