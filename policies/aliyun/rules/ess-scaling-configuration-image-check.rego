package infraguard.rules.aliyun.ess_scaling_configuration_image_check

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "ess-scaling-configuration-image-check",
	"name": {
		"en": "ESS Scaling Configuration Image Check",
		"zh": "弹性伸缩配置镜像检测",
	},
	"severity": "medium",
	"description": {
		"en": "ESS scaling configurations should use maintained images to ensure security and stability.",
		"zh": "弹性伸缩配置中镜像为保有中资源，视为合规。",
	},
	"reason": {
		"en": "The ESS scaling configuration may be using an image that is no longer maintained or available.",
		"zh": "弹性伸缩配置中使用的镜像可能已不再维护或不再可用。",
	},
	"recommendation": {
		"en": "Use images that are in maintained status. You can use ImageId or ImageFamily properties with valid image IDs.",
		"zh": "使用状态为保有中的镜像资源。可通过 ImageId 或 ImageFamily 属性指定有效镜像 ID。",
	},
	"resource_types": ["ALIYUN::ESS::ScalingConfiguration"],
}

# Check if scaling configuration has a valid image
has_valid_image(resource) if {
	image_id := helpers.get_property(resource, "ImageId", "")
	image_id != ""
}

has_valid_image(resource) if {
	image_family := helpers.get_property(resource, "ImageFamily", "")
	image_family != ""
}

# Deny rule: ESS scaling configurations must have a valid image
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ESS::ScalingConfiguration")
	not has_valid_image(resource)
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
