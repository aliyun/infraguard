package infraguard.rules.aliyun.ess_scaling_configuration_image_type_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "rule:aliyun:ess-scaling-configuration-image-type-check",
	"name": {
		"en": "ESS Scaling Configuration Image Type Check",
		"zh": "弹性伸缩配置中使用指定来源的镜像",
	},
	"severity": "medium",
	"description": {
		"en": "ESS scaling configurations should use images from specified sources for better security and management.",
		"zh": "弹性伸缩配置中镜像来源为指定类型的来源，视为合规。参数默认值为共享类型。",
	},
	"reason": {
		"en": "The ESS scaling configuration is not using an image from the specified source type.",
		"zh": "弹性伸缩配置中镜像来源非指定类型，可能存在安全风险或管理问题。",
	},
	"recommendation": {
		"en": "Use images from trusted sources. Set the image source type according to your security requirements.",
		"zh": "使用来自可信来源的镜像。根据安全要求设置镜像来源类型。",
	},
	"resource_types": ["ALIYUN::ESS::ScalingConfiguration"],
}

has_specified_image_type(resource) if {
	image_id := helpers.get_property(resource, "ImageId", "")
	image_id != ""
}

has_specified_image_type(resource) if {
	image_family := helpers.get_property(resource, "ImageFamily", "")
	image_family != ""
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ESS::ScalingConfiguration")
	not has_specified_image_type(resource)
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
