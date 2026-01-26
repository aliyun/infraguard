package infraguard.rules.aliyun.rds_public_access_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "rds-public-access-check",
	"name": {
		"en": "RDS Instance Public Access Check",
		"zh": "RDS 实例不配置公网地址",
	},
	"severity": "high",
	"description": {
		"en": "RDS instances should not be configured with public network addresses. Public access exposes databases to potential security threats from the internet.",
		"zh": "RDS 实例不应配置公网地址。公网访问会使数据库暴露于来自互联网的潜在安全威胁。",
	},
	"reason": {
		"en": "The RDS instance is configured with public network access, which exposes the database to security risks from the internet.",
		"zh": "RDS 实例配置了公网访问，使数据库暴露于来自互联网的安全风险。",
	},
	"recommendation": {
		"en": "Disable public network access for the RDS instance by setting AllocatePublicConnection to false or not configuring it.",
		"zh": "通过将 AllocatePublicConnection 设置为 false 或不配置该属性，禁用 RDS 实例的公网访问。",
	},
	"resource_types": ["ALIYUN::RDS::DBInstance"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::RDS::DBInstance")
	has_public_access(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "AllocatePublicConnection"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}

has_public_access(resource) if {
	resource.Properties.AllocatePublicConnection == true
}
