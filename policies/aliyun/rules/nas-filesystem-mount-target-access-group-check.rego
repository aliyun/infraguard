package infraguard.rules.aliyun.nas_filesystem_mount_target_access_group_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "nas-filesystem-mount-target-access-group-check",
	"name": {
		"en": "NAS Mount Target Access Group Check",
		"zh": "NAS 挂载点禁用默认权限组"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures NAS mount targets do not use the 'DEFAULT_VPC_GROUP_NAME'.",
		"zh": "确保 NAS 挂载点未使用'DEFAULT_VPC_GROUP_NAME'。"
	},
	"reason": {
		"en": "The default access group may have overly permissive rules.",
		"zh": "默认权限组可能拥有过于宽松的规则。"
	},
	"recommendation": {
		"en": "Use a custom access group with restricted rules for NAS mount targets.",
		"zh": "为 NAS 挂载点使用规则受限的自定义权限组。"
	},
	"resource_types": ["ALIYUN::NAS::MountTarget"],
}

is_compliant(resource) if {
	group := helpers.get_property(resource, "AccessGroupName", "DEFAULT_VPC_GROUP_NAME")
	group != "DEFAULT_VPC_GROUP_NAME"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::NAS::MountTarget")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "AccessGroupName"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
