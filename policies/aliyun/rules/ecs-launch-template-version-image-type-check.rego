package infraguard.rules.aliyun.ecs_launch_template_version_image_type_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rule:aliyun:ecs-launch-template-version-image-type-check",
	"name": {
		"en": "Launch Template Image Type Check",
		"zh": "启动模板镜像来源核查"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures ECS launch templates use authorized image types.",
		"zh": "确保 ECS 启动模板使用授权的镜像类型。"
	},
	"reason": {
		"en": "Restricting image sources in templates ensures consistent security baselines.",
		"zh": "在模板中限制镜像来源可确保一致的安全基线。"
	},
	"recommendation": {
		"en": "Update the launch template to use authorized images.",
		"zh": "更新启动模板以使用授权镜像。"
	},
	"resource_types": ["ALIYUN::ECS::LaunchTemplate"],
}

is_compliant(resource) if {
	# Check ImageId directly in Properties
	helpers.get_property(resource, "ImageId", null) != null
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::LaunchTemplate")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "ImageId"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
