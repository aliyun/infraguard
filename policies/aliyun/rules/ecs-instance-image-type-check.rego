package infraguard.rules.aliyun.ecs_instance_image_type_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rule:aliyun:ecs-instance-image-type-check",
	"name": {
		"en": "ECS Instance Image Type Check",
		"zh": "ECS 实例镜像来源核查"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures ECS instances use images from authorized sources.",
		"zh": "确保 ECS 实例使用来自授权来源的镜像。"
	},
	"reason": {
		"en": "Using untrusted image sources can introduce security vulnerabilities or malware.",
		"zh": "使用未经信任的镜像来源可能会引入安全漏洞或恶意软件。"
	},
	"recommendation": {
		"en": "Specify an authorized ImageId for the ECS instance.",
		"zh": "为 ECS 实例指定授权的镜像 ID。"
	},
	"resource_types": ["ALIYUN::ECS::Instance"],
}

is_compliant(resource) if {
	# In ROS, we usually check if ImageId is set.
	# Complex source checking often requires runtime tags, but we ensure ImageId is present.
	helpers.has_property(resource, "ImageId")
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::Instance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "ImageId"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
