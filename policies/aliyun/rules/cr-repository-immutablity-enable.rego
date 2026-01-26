package infraguard.rules.aliyun.cr_repository_immutablity_enable

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "cr-repository-immutablity-enable",
	"name": {
		"en": "Container Registry repository image version is immutable",
		"zh": "容器镜像服务镜像版本为不可变",
	},
	"description": {
		"en": "Container Registry repository image version is immutable, considered compliant.",
		"zh": "容器镜像服务镜像版本为不可变,视为合规。",
	},
	"severity": "low",
	"resource_types": ["ALIYUN::CR::Repository"],
	"reason": {
		"en": "Container Registry repository image version is not immutable",
		"zh": "容器镜像服务镜像版本不是不可变的",
	},
	"recommendation": {
		"en": "Enable tag immutability for Container Registry repository to prevent image tags from being overwritten",
		"zh": "为容器镜像服务仓库启用标签不可变性以防止镜像标签被覆盖",
	},
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::CR::Repository")

	# Check if TagImmutability is enabled
	# Only applicable when InstanceId is specified (Enterprise Edition)
	has_instance := helpers.has_property(resource, "InstanceId")
	has_instance

	tag_immutability := helpers.get_property(resource, "TagImmutability", false)
	not helpers.is_true(tag_immutability)

	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
