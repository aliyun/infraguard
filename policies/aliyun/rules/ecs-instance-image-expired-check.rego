package infraguard.rules.aliyun.ecs_instance_image_expired_check

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "ecs-instance-image-expired-check",
	"name": {
		"en": "ECS Instance Image Expired Check",
		"zh": "ECS 实例镜像过期检测",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that the image used by the ECS instance has not expired.",
		"zh": "确保 ECS 实例使用的镜像未过期。",
	},
	"reason": {
		"en": "Using an expired image may lead to security vulnerabilities and lack of support.",
		"zh": "使用过期的镜像可能导致安全漏洞和缺乏技术支持。",
	},
	"recommendation": {
		"en": "Update the ECS instance to use a supported, non-expired image.",
		"zh": "更新 ECS 实例以使用受支持、未过期的镜像。",
	},
	"resource_types": ["ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"],
}

deny contains result if {
	some name, resource in helpers.resources_by_types(["ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"])

	# Conceptual check
	helpers.has_property(resource, "ImageId")
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "ImageId"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
